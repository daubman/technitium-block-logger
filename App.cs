/*
Technitium DNS Server - Block Logger App
Copyright (C) 2026 Aaron Daubman

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

using DnsServerCore.ApplicationCommon;
using Microsoft.Data.Sqlite;
using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading.Channels;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.EDnsOptions;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace BlockLogger;

public sealed class App : IDnsApplication, IDnsQueryLogger, IDnsQueryLogs
{
    private static readonly JsonDocumentOptions _jsonParseOptions = new() { CommentHandling = JsonCommentHandling.Skip };

    private IDnsServer? _dnsServer;
    private bool _enableLogging;
    private int _maxLogDays;
    private int _maxLogRecords;
    private bool _enableVacuum;
    private int _maxQueueSize;
    private int _maxBatchSize;

    private string? _dbPath;
    private Channel<LogEntry>? _queue;
    private CancellationTokenSource? _cts;
    private Task? _consumerTask;
    private Task? _cleanupTask;

    private const int BULK_REMOVE_COUNT = 10000;
    private static readonly TimeSpan CleanupInterval = TimeSpan.FromMinutes(15);
    // Upper bound for the re-query dedup set. DirectQueryAsync responses are
    // documented as not logged, so entries may never be consumed - cap it so it
    // cannot grow unbounded on a busy server.
    private const int MAX_PENDING_REQUERY = 8192;
    // Re-queries run concurrently but bounded: each can take up to 500 ms, so a
    // burst of non-EDNS blocked queries would otherwise serialize into seconds
    // of delay inside a single batch.
    private const int MAX_CONCURRENT_REQUERIES = 8;
    // Pages reclaimed per cleanup cycle by incremental_vacuum (4KB pages ->
    // ~16 MB per pass). Bounded work avoids a full-VACUUM write lock.
    private const int INCREMENTAL_VACUUM_PAGES = 4096;

    private readonly ConcurrentDictionary<string, byte> _pendingRequery = new();

    public string? Description => "Enhanced query logger that captures block reason data (group, blocklist URL) from EDE responses. Drop-in replacement for Query Logs (Sqlite) with enriched blocking information visible in the built-in query log viewer.";

    public Task InitializeAsync(IDnsServer dnsServer, string? config)
    {
        _dnsServer = dnsServer;

        if (_cts is not null)
        {
            _cts.Cancel();
            _cts.Dispose();
        }

        if (config is not null)
        {
            using var doc = JsonDocument.Parse(config, _jsonParseOptions);
            var root = doc.RootElement;

            _enableLogging = root.TryGetProperty("enableLogging", out var el) ? el.GetBoolean() : true;
            _maxLogDays = root.TryGetProperty("maxLogDays", out el) ? el.GetInt32() : 30;
            _maxLogRecords = root.TryGetProperty("maxLogRecords", out el) ? el.GetInt32() : 0;
            _enableVacuum = root.TryGetProperty("enableVacuum", out el) ? el.GetBoolean() : false;
            _maxQueueSize = root.TryGetProperty("maxQueueSize", out el) ? el.GetInt32() : 200000;
            _maxBatchSize = root.TryGetProperty("maxBatchSize", out el) ? el.GetInt32() : 1000;
        }
        else
        {
            _enableLogging = true;
            _maxLogDays = 30;
            _maxLogRecords = 0;
            _enableVacuum = false;
            _maxQueueSize = 200000;
            _maxBatchSize = 1000;
        }

        if (!_enableLogging)
            return Task.CompletedTask;

        _dbPath = Path.Combine(dnsServer.ApplicationFolder, "querylogs.db");
        InitializeDatabase();

        _cts = new CancellationTokenSource();
        _queue = Channel.CreateBounded<LogEntry>(new BoundedChannelOptions(_maxQueueSize)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleReader = true,
            SingleWriter = false
        });

        _consumerTask = Task.Run(() => ConsumeAsync(_cts.Token));
        _cleanupTask = Task.Run(() => CleanupLoopAsync(_cts.Token));
        return Task.CompletedTask;
    }

    private void InitializeDatabase()
    {
        using var conn = new SqliteConnection($"Data Source={_dbPath}");
        conn.Open();

        using var cmd = conn.CreateCommand();
        // WAL lets the metrics collector and the web console read while the
        // consumer is inserting, instead of taking a database-wide write lock.
        cmd.CommandText = @"
            PRAGMA journal_mode=WAL;

            CREATE TABLE IF NOT EXISTS dns_logs (
                dlid INTEGER PRIMARY KEY,
                timestamp DATETIME NOT NULL,
                client_ip VARCHAR(39) NOT NULL,
                protocol TINYINT NOT NULL,
                response_type TINYINT NOT NULL,
                response_rtt REAL,
                rcode TINYINT NOT NULL,
                qname VARCHAR(255),
                qtype SMALLINT,
                qclass SMALLINT,
                answer TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_timestamp ON dns_logs(timestamp);
            CREATE INDEX IF NOT EXISTS idx_client_ip ON dns_logs(client_ip);
            CREATE INDEX IF NOT EXISTS idx_protocol ON dns_logs(protocol);
            CREATE INDEX IF NOT EXISTS idx_response_type ON dns_logs(response_type);
            CREATE INDEX IF NOT EXISTS idx_rcode ON dns_logs(rcode);
            CREATE INDEX IF NOT EXISTS idx_qname ON dns_logs(qname);
            CREATE INDEX IF NOT EXISTS idx_qtype ON dns_logs(qtype);
            CREATE INDEX IF NOT EXISTS idx_qclass ON dns_logs(qclass);
            CREATE INDEX IF NOT EXISTS idx_timestamp_client_ip ON dns_logs(timestamp, client_ip);
            CREATE INDEX IF NOT EXISTS idx_timestamp_qname ON dns_logs(timestamp, qname);
            CREATE INDEX IF NOT EXISTS idx_client_ip_qname ON dns_logs(client_ip, qname);
            CREATE INDEX IF NOT EXISTS idx_qname_qtype ON dns_logs(qname, qtype);
            CREATE INDEX IF NOT EXISTS idx_all ON dns_logs(timestamp, client_ip, protocol, response_type, rcode, qname, qtype, qclass);
        ";
        cmd.ExecuteNonQuery();

        if (_enableVacuum)
        {
            using var avCmd = conn.CreateCommand();
            avCmd.CommandText = "PRAGMA auto_vacuum";
            var mode = Convert.ToInt64(avCmd.ExecuteScalar());
            if (mode != 2)
            {
                try
                {
                    // Switching auto_vacuum on an existing database needs one
                    // VACUUM; startup is the least-bad time to pay that cost.
                    // Afterwards each cleanup cycle reclaims pages incrementally.
                    _dnsServer?.WriteLog("BlockLogger: switching querylogs.db to incremental auto-vacuum (one-time VACUUM)");
                    using var v = conn.CreateCommand();
                    v.CommandText = "PRAGMA auto_vacuum=INCREMENTAL; VACUUM;";
                    v.ExecuteNonQuery();
                }
                catch (Exception ex)
                {
                    // A competing reader can make VACUUM fail; the app must
                    // still load - it will be retried on the next restart.
                    _dnsServer?.WriteLog("BlockLogger: one-time VACUUM failed, will retry on restart: " + ex.Message);
                }
            }
        }
    }

    public async Task InsertLogAsync(DateTime timestamp, DnsDatagram request, IPEndPoint remoteEP,
        DnsTransportProtocol protocol, DnsDatagram response)
    {
        if (!_enableLogging || _queue is null)
            return;

        // Skip re-queries we initiated to avoid duplicate logging (DirectQueryAsync
        // responses are documented as not logged; the dedup is belt-and-braces).
        string requeryCacheKey = $"{remoteEP.Address}|{(request.Question.Count > 0 ? request.Question[0].Name : "")}";
        if (_pendingRequery.TryRemove(requeryCacheKey, out _))
            return;

        DnsServerResponseType responseType = response.Tag is null
            ? DnsServerResponseType.Recursive
            : (DnsServerResponseType)response.Tag;

        double? rtt = null;
        if (responseType == DnsServerResponseType.Recursive && response.Metadata is not null)
            rtt = response.Metadata.RoundTripTime;

        string? answer = null;
        if (response.Answer is null || response.Answer.Count == 0)
        {
            if (response.Truncation)
                answer = "[TRUNCATED]";
        }
        else if (response.Answer.Count > 2 && response.IsZoneTransfer)
        {
            answer = "[ZONE TRANSFER]";
        }
        else
        {
            var sb = new StringBuilder();
            foreach (var record in response.Answer)
            {
                if (sb.Length > 0)
                    sb.Append(", ");
                sb.Append(record.Type);
                sb.Append(' ');
                sb.Append(record.RDATA);
            }
            answer = sb.ToString();
        }

        var entry = new LogEntry
        {
            Timestamp = timestamp,
            ClientIp = remoteEP.Address,
            Protocol = protocol,
            ResponseType = responseType,
            ResponseRtt = rtt,
            Rcode = response.RCODE,
            Qname = request.Question.Count > 0 ? request.Question[0].Name.ToLowerInvariant() : null,
            Qtype = request.Question.Count > 0 ? request.Question[0].Type : null,
            Qclass = request.Question.Count > 0 ? request.Question[0].Class : null,
            Answer = answer
        };

        // Blocked responses only carry the EDE block reason when the client's
        // request negotiated EDNS. Extract it cheaply here; when absent, the
        // consumer re-queries off the request path so DNS is never delayed.
        if (responseType is DnsServerResponseType.Blocked
            or DnsServerResponseType.UpstreamBlocked
            or DnsServerResponseType.UpstreamBlockedCached)
        {
            entry.EdeInfo = ExtractBlockingEde(response);
            if (entry.EdeInfo is null && request.Question.Count > 0)
            {
                entry.NeedsEde = true;
                entry.Question = request.Question[0];
                entry.RemoteEP = remoteEP;
            }

            if (entry.Answer is null)
                entry.Answer = "BLOCKED";
        }

        _queue.Writer.TryWrite(entry);
    }

    private async Task<string?> ResolveBlockReasonAsync(DnsQuestionRecord question, IPEndPoint remoteEP)
    {
        try
        {
            string cacheKey = $"{remoteEP.Address}|{question.Name}";
            if (_pendingRequery.Count < MAX_PENDING_REQUERY)
                _pendingRequery.TryAdd(cacheKey, 0);

            var ednsRequest = new DnsDatagram(
                0, false, DnsOpcode.StandardQuery, false, false, true, false, false, false,
                DnsResponseCode.NoError,
                new[] { question },
                udpPayloadSize: DnsDatagram.EDNS_DEFAULT_UDP_PAYLOAD_SIZE);

            var ednsResponse = await _dnsServer!.DirectQueryAsync(ednsRequest, remoteEP, 500);
            return ExtractBlockingEde(ednsResponse);
        }
        catch
        {
            return null;
        }
    }

    private static string? ExtractBlockingEde(DnsDatagram response)
    {
        if (response.EDNS is not null)
        {
            foreach (var option in response.EDNS.Options)
            {
                if (option.Code == EDnsOptionCode.EXTENDED_DNS_ERROR &&
                    option.Data is EDnsExtendedDnsErrorOptionData edeData &&
                    edeData.InfoCode == EDnsExtendedDnsErrorCode.Blocked)
                {
                    return edeData.ExtraText;
                }
            }
        }

        if (response.DnsClientExtendedErrors is not null)
        {
            foreach (var ede in response.DnsClientExtendedErrors)
            {
                if (ede.InfoCode == EDnsExtendedDnsErrorCode.Blocked)
                    return ede.ExtraText;
            }
        }

        return null;
    }

    private static void ParseEdeInfo(string info, out string? source, out string? group,
        out string? blockListUrl, out string? domain)
    {
        source = null;
        group = null;
        blockListUrl = null;
        domain = null;

        foreach (var part in info.Split(';', StringSplitOptions.TrimEntries))
        {
            var eqIdx = part.IndexOf('=');
            if (eqIdx < 0) continue;

            var key = part[..eqIdx].Trim();
            var value = part[(eqIdx + 1)..].Trim();

            switch (key)
            {
                case "source": source = value; break;
                case "group": group = value; break;
                case "blockListUrl":
                case "regexBlockListUrl": blockListUrl = value; break;
                case "domain":
                case "regex": domain = value; break;
            }
        }
    }

    private static string FriendlyBlocklistName(string url)
    {
        if (url.Contains("oisd.nl/domainswild") && !url.Contains("nsfw"))
            return "OISD Big";
        if (url.Contains("nsfw.oisd.nl"))
            return "OISD NSFW";
        if (url.Contains("hagezi") && url.Contains("tif"))
            return "HaGeZi TIF";
        if (url.Contains("hagezi") && url.Contains("normal"))
            return "HaGeZi Normal";
        if (url.Contains("hagezi"))
            return "HaGeZi";
        if (url.Contains("adguard"))
            return "AdGuard";
        if (url.Contains("easylist"))
            return "EasyList";

        var uri = new Uri(url);
        var path = uri.AbsolutePath;
        var lastSlash = path.LastIndexOf('/');
        return lastSlash >= 0 ? path[(lastSlash + 1)..] : uri.Host;
    }

    // IDnsQueryLogs implementation
    public Task<DnsLogPage> QueryLogsAsync(long pageNumber, int entriesPerPage, bool descendingOrder,
        DateTime? start, DateTime? end, IPAddress? clientIpAddress,
        DnsTransportProtocol? protocol, DnsServerResponseType? responseType,
        DnsResponseCode? rcode, string? qname, DnsResourceRecordType? qtype, DnsClass? qclass)
    {
        if (_dbPath is null)
            return Task.FromResult(new DnsLogPage(pageNumber, 0, 0, Array.Empty<DnsLogEntry>()));

        if (pageNumber == 0)
            pageNumber = 1;

        if (qname is not null)
            qname = qname.ToLowerInvariant();

        using var conn = new SqliteConnection($"Data Source={_dbPath};Mode=ReadOnly");
        conn.Open();

        var where = new List<string>();
        var parameters = new List<SqliteParameter>();

        if (start.HasValue)
        {
            where.Add("timestamp >= $start");
            parameters.Add(new SqliteParameter("$start", start.Value.ToString("O")));
        }
        if (end.HasValue)
        {
            where.Add("timestamp <= $end");
            parameters.Add(new SqliteParameter("$end", end.Value.ToString("O")));
        }
        if (clientIpAddress is not null)
        {
            where.Add("client_ip = $cip");
            parameters.Add(new SqliteParameter("$cip", clientIpAddress.ToString()));
        }
        if (protocol.HasValue)
        {
            where.Add("protocol = $proto");
            parameters.Add(new SqliteParameter("$proto", (byte)protocol.Value));
        }
        if (responseType.HasValue)
        {
            where.Add("response_type = $rtype");
            parameters.Add(new SqliteParameter("$rtype", (byte)responseType.Value));
        }
        if (rcode.HasValue)
        {
            where.Add("rcode = $rcode");
            parameters.Add(new SqliteParameter("$rcode", (byte)rcode.Value));
        }
        if (qname is not null)
        {
            // Upstream convention: exact match by default, '*' maps to a SQL
            // wildcard so 'foo*' stays index-usable as a prefix search.
            if (qname.Contains('*'))
            {
                where.Add("qname LIKE $qname");
                parameters.Add(new SqliteParameter("$qname", qname.Replace("*", "%")));
            }
            else
            {
                where.Add("qname = $qname");
                parameters.Add(new SqliteParameter("$qname", qname));
            }
        }
        if (qtype.HasValue)
        {
            where.Add("qtype = $qtype");
            parameters.Add(new SqliteParameter("$qtype", (short)qtype.Value));
        }
        if (qclass.HasValue)
        {
            where.Add("qclass = $qclass");
            parameters.Add(new SqliteParameter("$qclass", (short)qclass.Value));
        }

        var whereClause = where.Count > 0 ? "WHERE " + string.Join(" AND ", where) : "";
        var orderDir = descendingOrder ? "DESC" : "ASC";

        using var countCmd = conn.CreateCommand();
        countCmd.CommandText = $"SELECT COUNT(*) FROM dns_logs {whereClause}";
        countCmd.Parameters.AddRange(parameters.ToArray());
        var totalEntries = (long)countCmd.ExecuteScalar()!;

        var totalPages = totalEntries / entriesPerPage;
        if (totalEntries % entriesPerPage > 0) totalPages++;
        if (totalPages < 1)
            pageNumber = 1;
        else if (pageNumber > totalPages || pageNumber < 0)
            pageNumber = totalPages;

        var offset = (pageNumber - 1) * entriesPerPage;

        using var queryCmd = conn.CreateCommand();
        queryCmd.CommandText = $@"
            SELECT dlid, timestamp, client_ip, protocol, response_type, response_rtt,
                   rcode, qname, qtype, qclass, answer
            FROM dns_logs {whereClause}
            ORDER BY dlid {orderDir}
            LIMIT $limit OFFSET $offset";
        foreach (var p in parameters)
        {
            var clone = queryCmd.CreateParameter();
            clone.ParameterName = p.ParameterName;
            clone.Value = p.Value;
            queryCmd.Parameters.Add(clone);
        }
        queryCmd.Parameters.AddWithValue("$limit", entriesPerPage);
        queryCmd.Parameters.AddWithValue("$offset", offset);

        var entries = new List<DnsLogEntry>();
        using var reader = queryCmd.ExecuteReader();
        long rowNum = descendingOrder ? totalEntries - offset : offset + 1;

        while (reader.Read())
        {
            var ts = DateTime.Parse(reader.GetString(1));
            var clientIp = IPAddress.Parse(reader.GetString(2));
            var proto = (DnsTransportProtocol)reader.GetByte(3);
            var respType = (DnsServerResponseType)reader.GetByte(4);
            double? respRtt = reader.IsDBNull(5) ? null : reader.GetDouble(5);
            var rc = (DnsResponseCode)reader.GetByte(6);

            DnsQuestionRecord? question = null;
            if (!reader.IsDBNull(7))
            {
                var name = reader.GetString(7);
                var qt = reader.IsDBNull(8) ? DnsResourceRecordType.A : (DnsResourceRecordType)reader.GetInt32(8);
                var qc = reader.IsDBNull(9) ? DnsClass.IN : (DnsClass)reader.GetInt32(9);
                question = new DnsQuestionRecord(name, qt, qc);
            }

            var ans = reader.IsDBNull(10) ? null : reader.GetString(10);

            entries.Add(new DnsLogEntry(
                descendingOrder ? rowNum-- : rowNum++,
                ts, clientIp, proto, respType, respRtt, rc, question, ans));
        }

        return Task.FromResult(new DnsLogPage(pageNumber, totalPages, totalEntries, entries));
    }

    private async Task ConsumeAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var entries = new List<LogEntry>();

                await _queue!.Reader.WaitToReadAsync(ct);

                while (entries.Count < _maxBatchSize && _queue.Reader.TryRead(out var entry))
                    entries.Add(entry);

                if (entries.Count > 0)
                    await InsertBatchAsync(entries, ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _dnsServer?.WriteLog("BlockLogger: Consumer error: " + ex.Message);
                await Task.Delay(1000, ct);
            }
        }
    }

    private async Task InsertBatchAsync(List<LogEntry> entries, CancellationToken ct)
    {
        // Entries logged without a client-EDNS response need a re-query to
        // learn the block reason. Resolve them concurrently (bounded) rather
        // than serially so a burst cannot stall the batch.
        var unresolved = new List<LogEntry>();
        foreach (var e in entries)
            if (e.EdeInfo is null && e.NeedsEde && e.Question is not null && e.RemoteEP is not null)
                unresolved.Add(e);

        if (unresolved.Count > 0)
        {
            using var sem = new SemaphoreSlim(MAX_CONCURRENT_REQUERIES);
            await Task.WhenAll(unresolved.Select(async e =>
            {
                try
                {
                    await sem.WaitAsync(ct);
                    try { e.EdeInfo = await ResolveBlockReasonAsync(e.Question!, e.RemoteEP!); }
                    finally { sem.Release(); }
                }
                catch (OperationCanceledException) { }
            }));
        }

        // Format the EDE block reason into the answer field.
        foreach (var e in entries)
        {
            var edeInfo = e.EdeInfo;
            if (edeInfo is null)
                continue;

            ParseEdeInfo(edeInfo, out _, out var group, out var blockListUrl, out _);
            var sb = new StringBuilder();
            if (group is not null)
            {
                sb.Append("[group=");
                sb.Append(group);
                if (blockListUrl is not null)
                {
                    sb.Append(", list=");
                    sb.Append(FriendlyBlocklistName(blockListUrl));
                }
                sb.Append("] ");
            }
            sb.Append(e.Answer ?? "BLOCKED");
            e.Answer = sb.ToString();

            if (ct.IsCancellationRequested)
                break;
        }

        using var conn = new SqliteConnection($"Data Source={_dbPath}");
        conn.Open();

        using var tx = conn.BeginTransaction();
        using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = @"
            INSERT INTO dns_logs (timestamp, client_ip, protocol, response_type, response_rtt,
                                  rcode, qname, qtype, qclass, answer)
            VALUES ($ts, $cip, $proto, $rtype, $rtt, $rcode, $qname, $qtype, $qclass, $answer)";

        var pTs = cmd.Parameters.Add("$ts", SqliteType.Text);
        var pCip = cmd.Parameters.Add("$cip", SqliteType.Text);
        var pProto = cmd.Parameters.Add("$proto", SqliteType.Integer);
        var pRtype = cmd.Parameters.Add("$rtype", SqliteType.Integer);
        var pRtt = cmd.Parameters.Add("$rtt", SqliteType.Real);
        var pRcode = cmd.Parameters.Add("$rcode", SqliteType.Integer);
        var pQname = cmd.Parameters.Add("$qname", SqliteType.Text);
        var pQtype = cmd.Parameters.Add("$qtype", SqliteType.Integer);
        var pQclass = cmd.Parameters.Add("$qclass", SqliteType.Integer);
        var pAnswer = cmd.Parameters.Add("$answer", SqliteType.Text);

        cmd.Prepare();

        foreach (var e in entries)
        {
            pTs.Value = e.Timestamp.ToString("O");
            pCip.Value = e.ClientIp.ToString();
            pProto.Value = (byte)e.Protocol;
            pRtype.Value = (byte)e.ResponseType;
            pRtt.Value = e.ResponseRtt.HasValue ? (object)e.ResponseRtt.Value : DBNull.Value;
            pRcode.Value = (byte)e.Rcode;
            pQname.Value = e.Qname is not null ? (object)e.Qname : DBNull.Value;
            pQtype.Value = e.Qtype.HasValue ? (object)(short)e.Qtype.Value : DBNull.Value;
            pQclass.Value = e.Qclass.HasValue ? (object)(short)e.Qclass.Value : DBNull.Value;
            pAnswer.Value = e.Answer is not null ? (object)e.Answer : DBNull.Value;

            cmd.ExecuteNonQuery();
        }

        tx.Commit();
    }

    private async Task CleanupLoopAsync(CancellationToken ct)
    {
        // First run shortly after startup, then every 15 minutes - small batched
        // deletes instead of one giant transaction on a multi-GB table.
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(CleanupInterval, ct);
                RunCleanup();
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _dnsServer?.WriteLog("BlockLogger: Cleanup error: " + ex.Message);
            }
        }
    }

    private void RunCleanup()
    {
        using var conn = new SqliteConnection($"Data Source={_dbPath}");
        conn.Open();

        var deleted = 0;

        if (_maxLogDays > 0)
        {
            var cutoff = DateTime.UtcNow.AddDays(-_maxLogDays).ToString("O");
            deleted += BatchRemove(conn, "timestamp < $cutoff", ("$cutoff", cutoff));
        }

        if (_maxLogRecords > 0)
        {
            using var countCmd = conn.CreateCommand();
            countCmd.CommandText = "SELECT COUNT(*) FROM dns_logs";
            var total = (long)countCmd.ExecuteScalar()!;
            var excess = total - _maxLogRecords;
            if (excess > 0)
                deleted += BatchRemoveOldest(conn, excess);
        }

        if (deleted > 0)
        {
            _dnsServer?.WriteLog($"BlockLogger: Cleaned up {deleted} old log entries");

            if (_enableVacuum)
            {
                using var vacuumCmd = conn.CreateCommand();
                vacuumCmd.CommandText = $"PRAGMA incremental_vacuum({INCREMENTAL_VACUUM_PAGES})";
                vacuumCmd.ExecuteNonQuery();
            }
        }
    }

    private static int BatchRemove(SqliteConnection conn, string predicate, params (string, object)[] parms)
    {
        var total = 0;
        while (true)
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = $"DELETE FROM dns_logs WHERE dlid IN (SELECT dlid FROM dns_logs WHERE {predicate} LIMIT {BULK_REMOVE_COUNT})";
            foreach (var (name, value) in parms)
                cmd.Parameters.AddWithValue(name, value);
            var n = cmd.ExecuteNonQuery();
            total += n;
            if (n < BULK_REMOVE_COUNT)
                return total;
        }
    }

    private static int BatchRemoveOldest(SqliteConnection conn, long count)
    {
        var remaining = count;
        var total = 0;
        while (remaining > 0)
        {
            var batch = (int)Math.Min(remaining, BULK_REMOVE_COUNT);
            using var cmd = conn.CreateCommand();
            cmd.CommandText = $"DELETE FROM dns_logs WHERE dlid IN (SELECT dlid FROM dns_logs ORDER BY dlid LIMIT {batch})";
            total += cmd.ExecuteNonQuery();
            remaining -= batch;
        }
        return total;
    }

    public void Dispose()
    {
        _cts?.Cancel();
        _queue?.Writer.Complete();

        try { _consumerTask?.Wait(5000); } catch { }
        try { _cleanupTask?.Wait(2000); } catch { }

        _cts?.Dispose();
    }
}

internal sealed class LogEntry
{
    public DateTime Timestamp { get; init; }
    public IPAddress ClientIp { get; init; } = IPAddress.Loopback;
    public DnsTransportProtocol Protocol { get; init; }
    public DnsServerResponseType ResponseType { get; init; }
    public double? ResponseRtt { get; init; }
    public DnsResponseCode Rcode { get; init; }
    public string? Qname { get; init; }
    public DnsResourceRecordType? Qtype { get; init; }
    public DnsClass? Qclass { get; init; }
    public string? Answer { get; set; }

    // EDE block reason extracted from the response when present; NeedsEde marks
    // entries where the consumer must re-query through the pipeline to get it.
    public string? EdeInfo { get; set; }
    public bool NeedsEde { get; set; }
    public DnsQuestionRecord? Question { get; set; }
    public IPEndPoint? RemoteEP { get; set; }
}
