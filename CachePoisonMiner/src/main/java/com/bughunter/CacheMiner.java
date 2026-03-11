package com.bughunter;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

public class CacheMiner implements BurpExtension, ContextMenuItemsProvider {

    private MontoyaApi api;
    private final MinerTableModel tableModel = new MinerTableModel();
    private ExecutorService executor;
    private HttpRequestEditor requestViewer;
    private HttpResponseEditor responseViewer;
    private final SecureRandom secureRandom = new SecureRandom();
    private final AtomicBoolean scanning = new AtomicBoolean(false);

    private JProgressBar progressBar;
    private JLabel statusLabel;
    private JButton cancelButton;

    private static final int MAX_RESULTS = 10_000;
    private static final int THREAD_POOL_SIZE = 10;
    private static final int SNIPPET_CONTEXT = 50;

    // --- TARGET HEADERS (Expanded - Potential Unkeyed Inputs) ---
    private static final List<String> MINING_HEADERS = Arrays.asList(
            "X-Forwarded-Host", "X-Host", "X-Forwarded-Server",
            "X-Forwarded-Scheme", "X-Forwarded-Proto", "X-Forwarded-For",
            "X-Forwarded-Port", "X-Forwarded-Prefix", "Forwarded",
            "X-Original-URL", "X-Rewrite-URL", "X-Original-Host",
            "X-Real-IP", "X-Client-IP", "Fastly-Client-IP", "True-Client-IP",
            "CF-Connecting-IP", "X-Azure-ClientIP", "X-ProxyUser-Ip",
            "X-Custom-IP-Authorization",
            "X-Frame-Options", "Origin", "Referer",
            "X-Originating-IP", "X-Remote-IP", "X-Remote-Addr",
            "X-Cluster-Client-IP", "X-Forwarded", "Via",
            "X-WAP-Profile", "X-ATT-DeviceId", "Accept-Language"
    );

    // --- COMMON UNKEYED PARAMETERS ---
    private static final List<String> MINING_PARAMS = Arrays.asList(
            "utm_source", "utm_medium", "utm_campaign", "utm_content", "utm_term",
            "fbclid", "gclid", "msclkid", "mc_cid", "mc_eid",
            "callback", "jsonp", "_", "cachebust", "nocache",
            "redirect", "url", "next", "dest", "return",
            "debug", "test", "dev", "preview", "draft"
    );

    // --- COMMON UNKEYED COOKIES ---
    private static final List<String> MINING_COOKIES = Arrays.asList(
            "language", "lang", "locale", "region", "country",
            "currency", "theme", "dark_mode", "display",
            "tracking_id", "visitor_id", "campaign"
    );

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Cache Poisoning Miner");

        executor = Executors.newFixedThreadPool(THREAD_POOL_SIZE);

        api.extension().registerUnloadingHandler(() -> {
            scanning.set(false);
            executor.shutdownNow();
            try {
                executor.awaitTermination(3, TimeUnit.SECONDS);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
        });

        SwingUtilities.invokeLater(this::buildUI);
        api.userInterface().registerContextMenuItemsProvider(this);
        api.logging().logToOutput("[*] Cache Poisoning Miner v2.0 loaded. Right-click a request to start mining.");
    }

    // ==================== UI ====================

    private void buildUI() {
        UserInterface ui = api.userInterface();

        JTable table = new JTable(tableModel);
        table.setFont(new Font("SansSerif", Font.PLAIN, 12));
        table.setRowHeight(24);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setIntercellSpacing(new Dimension(1, 1));
        table.getTableHeader().setReorderingAllowed(false);
        table.getTableHeader().setFont(new Font("SansSerif", Font.BOLD, 12));

        table.getColumnModel().getColumn(0).setPreferredWidth(40);
        table.getColumnModel().getColumn(0).setMaxWidth(50);
        table.getColumnModel().getColumn(1).setPreferredWidth(70);
        table.getColumnModel().getColumn(1).setMaxWidth(80);
        table.getColumnModel().getColumn(2).setPreferredWidth(170);
        table.getColumnModel().getColumn(3).setPreferredWidth(90);
        table.getColumnModel().getColumn(3).setMaxWidth(120);
        table.getColumnModel().getColumn(4).setPreferredWidth(100);
        table.getColumnModel().getColumn(4).setMaxWidth(180);
        table.getColumnModel().getColumn(5).setPreferredWidth(100);
        table.getColumnModel().getColumn(5).setMaxWidth(130);
        table.getColumnModel().getColumn(6).setPreferredWidth(500);

        table.setDefaultRenderer(Object.class, new RiskCellRenderer());

        requestViewer = ui.createHttpRequestEditor(EditorOptions.READ_ONLY);
        responseViewer = ui.createHttpResponseEditor(EditorOptions.READ_ONLY);

        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = table.getSelectedRow();
                if (row >= 0 && row < tableModel.getRowCount()) {
                    MinerResult result = tableModel.getResult(row);
                    if (result != null && result.requestResponse != null) {
                        requestViewer.setRequest(result.requestResponse.request());
                        if (result.requestResponse.response() != null) {
                            responseViewer.setResponse(result.requestResponse.response());
                        }
                    }
                }
            }
        });

        // Context menu
        JPopupMenu popupMenu = new JPopupMenu();
        JMenuItem confirmItem = new JMenuItem("Re-confirm Poisoning");
        JMenuItem deleteItem = new JMenuItem("Delete Selected");
        JMenuItem clearItem = new JMenuItem("Clear All Results");

        confirmItem.addActionListener(e -> {
            int row = table.getSelectedRow();
            if (row != -1) {
                MinerResult result = tableModel.getResult(row);
                if (result != null) executor.submit(() -> reconfirmPoisoning(result));
            }
        });
        deleteItem.addActionListener(e -> {
            int row = table.getSelectedRow();
            if (row != -1) tableModel.removeRow(row);
        });
        clearItem.addActionListener(e -> tableModel.clear());

        popupMenu.add(confirmItem);
        popupMenu.addSeparator();
        popupMenu.add(deleteItem);
        popupMenu.addSeparator();
        popupMenu.add(clearItem);

        table.addMouseListener(new MouseAdapter() {
            @Override public void mouseReleased(MouseEvent e) { showPopup(e); }
            @Override public void mousePressed(MouseEvent e) { showPopup(e); }
            private void showPopup(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    int row = table.rowAtPoint(e.getPoint());
                    if (row != -1 && !table.isRowSelected(row)) {
                        table.setRowSelectionInterval(row, row);
                    }
                    popupMenu.show(e.getComponent(), e.getX(), e.getY());
                }
            }
        });

        // Toolbar
        JToolBar toolbar = new JToolBar();
        toolbar.setFloatable(false);
        toolbar.setBorder(BorderFactory.createEmptyBorder(4, 6, 4, 6));

        JButton exportCsvBtn = new JButton("Export CSV");
        JButton exportJsonBtn = new JButton("Export JSON");
        JButton clearBtn = new JButton("Clear All");
        cancelButton = new JButton("Cancel Scan");
        cancelButton.setEnabled(false);

        exportCsvBtn.addActionListener(e -> exportResults("csv"));
        exportJsonBtn.addActionListener(e -> exportResults("json"));
        clearBtn.addActionListener(e -> tableModel.clear());
        cancelButton.addActionListener(e -> scanning.set(false));

        toolbar.add(exportCsvBtn);
        toolbar.addSeparator(new Dimension(6, 0));
        toolbar.add(exportJsonBtn);
        toolbar.addSeparator(new Dimension(6, 0));
        toolbar.add(clearBtn);
        toolbar.add(Box.createHorizontalGlue());
        toolbar.add(cancelButton);

        // Status bar
        JPanel statusBar = new JPanel(new BorderLayout(8, 0));
        statusBar.setBorder(BorderFactory.createEmptyBorder(3, 8, 3, 8));
        statusLabel = new JLabel("Ready");
        progressBar = new JProgressBar(0, 100);
        progressBar.setPreferredSize(new Dimension(220, 16));
        progressBar.setStringPainted(true);
        progressBar.setVisible(false);
        statusBar.add(statusLabel, BorderLayout.WEST);
        statusBar.add(progressBar, BorderLayout.EAST);

        // Layout
        JPanel topPanel = new JPanel(new BorderLayout());
        topPanel.add(toolbar, BorderLayout.NORTH);
        JScrollPane tableScroll = new JScrollPane(table);
        topPanel.add(tableScroll, BorderLayout.CENTER);
        topPanel.add(statusBar, BorderLayout.SOUTH);

        JSplitPane editorSplit = new JSplitPane(
                JSplitPane.HORIZONTAL_SPLIT,
                requestViewer.uiComponent(), responseViewer.uiComponent());
        editorSplit.setResizeWeight(0.5);

        JSplitPane mainSplit = new JSplitPane(
                JSplitPane.VERTICAL_SPLIT, topPanel, editorSplit);
        mainSplit.setResizeWeight(0.4);

        api.userInterface().registerSuiteTab("Cache Miner", mainSplit);
    }

    // ==================== CANARY & CACHE BUSTER ====================

    private String generateCanary() {
        byte[] bytes = new byte[12];
        secureRandom.nextBytes(bytes);
        StringBuilder sb = new StringBuilder("cpm-");
        for (byte b : bytes) sb.append(String.format("%02x", b & 0xFF));
        return sb.toString();
    }

    private String generateCacheBuster() {
        byte[] bytes = new byte[8];
        secureRandom.nextBytes(bytes);
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b & 0xFF));
        return sb.toString();
    }

    private String appendParam(String path, String param) {
        return path.contains("?") ? path + "&" + param : path + "?" + param;
    }

    // ==================== CONTEXT MENU ====================

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        if (event.messageEditorRequestResponse().isEmpty()) return null;

        MessageEditorHttpRequestResponse editor = event.messageEditorRequestResponse().get();

        JMenu mineMenu = new JMenu("Cache Poison Miner");
        JMenuItem mineAll = new JMenuItem("Mine All (Headers + Params + Cookies)");
        JMenuItem mineHeaders = new JMenuItem("Mine Headers Only");
        JMenuItem mineParams = new JMenuItem("Mine Parameters Only");
        JMenuItem mineCookies = new JMenuItem("Mine Cookies Only");

        mineAll.addActionListener(l -> launchScan(editor.requestResponse(), true, true, true));
        mineHeaders.addActionListener(l -> launchScan(editor.requestResponse(), true, false, false));
        mineParams.addActionListener(l -> launchScan(editor.requestResponse(), false, true, false));
        mineCookies.addActionListener(l -> launchScan(editor.requestResponse(), false, false, true));

        mineMenu.add(mineAll);
        mineMenu.addSeparator();
        mineMenu.add(mineHeaders);
        mineMenu.add(mineParams);
        mineMenu.add(mineCookies);

        List<Component> menuList = new ArrayList<>();
        menuList.add(mineMenu);
        return menuList;
    }

    private void launchScan(HttpRequestResponse rr, boolean headers, boolean params, boolean cookies) {
        Thread coordinator = new Thread(() -> startMining(rr, headers, params, cookies), "CacheMiner-Coordinator");
        coordinator.setDaemon(true);
        coordinator.start();
    }

    // ==================== MINING ENGINE ====================

    private void startMining(HttpRequestResponse baseRR, boolean mineHeaders, boolean mineParams, boolean mineCookies) {
        if (scanning.getAndSet(true)) {
            api.logging().logToOutput("[!] Scan already in progress.");
            return;
        }

        HttpRequest originalRequest = baseRR.request();
        String url = originalRequest.url();
        api.logging().logToOutput("[*] Starting cache mining on: " + url);

        SwingUtilities.invokeLater(() -> {
            cancelButton.setEnabled(true);
            statusLabel.setText("Scanning: " + url);
            progressBar.setValue(0);
            progressBar.setVisible(true);
        });

        try {
            // --- Baseline request ---
            String baselineBuster = "cb=" + generateCacheBuster();
            String baselinePath = appendParam(originalRequest.path(), baselineBuster);
            HttpRequestResponse baselineRR = api.http().sendRequest(originalRequest.withPath(baselinePath));

            if (baselineRR.response() == null) {
                api.logging().logToError("[!] Baseline request got no response. Aborting.");
                return;
            }

            String baselineBody = baselineRR.response().bodyToString();
            int baselineLength = baselineBody.length();
            api.logging().logToOutput("[*] Baseline response length: " + baselineLength);

            // --- Build task list ---
            List<MiningTask> tasks = new ArrayList<>();
            if (mineHeaders) {
                for (String h : MINING_HEADERS) tasks.add(new MiningTask("Header", h));
            }
            if (mineParams) {
                for (String p : MINING_PARAMS) tasks.add(new MiningTask("Param", p));
            }
            if (mineCookies) {
                for (String c : MINING_COOKIES) tasks.add(new MiningTask("Cookie", c));
            }

            int totalTasks = tasks.size();
            AtomicInteger completed = new AtomicInteger(0);

            // --- Submit probes in parallel ---
            List<Future<?>> futures = new ArrayList<>();
            for (MiningTask task : tasks) {
                Future<?> future = executor.submit(() -> {
                    if (!scanning.get()) return;
                    try {
                        probeInput(originalRequest, task, baselineBody, baselineLength);
                    } catch (Exception e) {
                        api.logging().logToError("Error probing " + task.type + " " + task.name + ": " + e.getMessage());
                    } finally {
                        int done = completed.incrementAndGet();
                        int pct = (int) ((done / (double) totalTasks) * 100);
                        SwingUtilities.invokeLater(() -> {
                            progressBar.setValue(pct);
                            statusLabel.setText("Scanning: " + done + "/" + totalTasks + " probes completed");
                        });
                    }
                });
                futures.add(future);
            }

            for (Future<?> f : futures) {
                try { f.get(); } catch (CancellationException | InterruptedException | ExecutionException ignored) {}
            }

        } catch (Exception e) {
            api.logging().logToError("[!] Mining failed: " + e.getMessage());
        } finally {
            scanning.set(false);
            SwingUtilities.invokeLater(() -> {
                cancelButton.setEnabled(false);
                progressBar.setVisible(false);
                statusLabel.setText("Scan complete. " + tableModel.getRowCount() + " results.");
            });
            api.logging().logToOutput("[*] Mining complete.");
        }
    }

    private void probeInput(HttpRequest originalRequest, MiningTask task, String baselineBody, int baselineLength) {
        String canary = generateCanary();
        String buster = "cb=" + generateCacheBuster();
        String bustedPath = appendParam(originalRequest.path(), buster);

        HttpRequest attackRequest;
        switch (task.type) {
            case "Header":
                attackRequest = originalRequest
                        .withPath(bustedPath)
                        .withRemovedHeader(task.name)
                        .withHeader(HttpHeader.httpHeader(task.name, canary));
                break;
            case "Param":
                attackRequest = originalRequest.withPath(appendParam(bustedPath, task.name + "=" + canary));
                break;
            case "Cookie":
                String existing = "";
                for (HttpHeader h : originalRequest.headers()) {
                    if (h.name().equalsIgnoreCase("Cookie")) { existing = h.value(); break; }
                }
                String cookieVal = existing.isEmpty() ? task.name + "=" + canary : existing + "; " + task.name + "=" + canary;
                attackRequest = originalRequest
                        .withPath(bustedPath)
                        .withRemovedHeader("Cookie")
                        .withHeader(HttpHeader.httpHeader("Cookie", cookieVal));
                break;
            default:
                return;
        }

        HttpRequestResponse response = api.http().sendRequest(attackRequest);

        if (response.response() == null) {
            api.logging().logToError("[!] No response for " + task.type + ": " + task.name);
            return;
        }

        String body = response.response().bodyToString();

        if (body.contains(canary)) {
            CacheStatus cacheStatus = analyzeCacheability(response);
            String snippet = extractSnippet(body, canary);
            String risk = determineRisk(true, cacheStatus);

            MinerResult result = new MinerResult(
                    task.type, task.name, risk,
                    cacheStatus.label, "Pending",
                    snippet, response, canary);
            addResultSafe(result);

            api.logging().logToOutput("[!] REFLECTED - " + task.type + ": " + task.name + " | Risk: " + risk);

            // --- Automatic confirmation probe for cacheable reflections ---
            if (cacheStatus.isCacheable) {
                autoConfirm(originalRequest, bustedPath, task, canary, result);
            } else {
                updateResult(result, r -> r.confirmed = "N/A");
            }
        } else {
            int lengthDiff = Math.abs(body.length() - baselineLength);
            if (lengthDiff > 50) {
                addResultSafe(new MinerResult(
                        task.type, task.name, "Info",
                        "Unknown", "N/A",
                        "Response differs by " + lengthDiff + " bytes (no direct reflection)",
                        response, canary));
            }
        }
    }

    // ==================== CONFIRMATION ====================

    private void autoConfirm(HttpRequest originalRequest, String bustedPath, MiningTask task, String canary, MinerResult result) {
        if (!scanning.get()) return;
        try {
            Thread.sleep(500);

            // Send a CLEAN request to the same cache-busted URL (same cache key)
            HttpRequest cleanReq = originalRequest.withPath(bustedPath);
            HttpRequestResponse cleanResponse = api.http().sendRequest(cleanReq);

            if (cleanResponse.response() != null && cleanResponse.response().bodyToString().contains(canary)) {
                updateResult(result, r -> {
                    r.confirmed = "YES - POISONED!";
                    r.risk = "Critical";
                    r.requestResponse = cleanResponse;
                });
                api.logging().logToOutput("[!!!] CONFIRMED CACHE POISONING: " + task.type + " " + task.name);
            } else {
                updateResult(result, r -> r.confirmed = "No");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (Exception e) {
            api.logging().logToError("Error confirming " + task.name + ": " + e.getMessage());
        }
    }

    private void reconfirmPoisoning(MinerResult result) {
        if (result.requestResponse == null) return;

        HttpRequest req = result.requestResponse.request();
        HttpRequest cleanReq = "Header".equals(result.type) ? req.withRemovedHeader(result.inputName) : req;

        try {
            HttpRequestResponse cleanResponse = api.http().sendRequest(cleanReq);
            if (cleanResponse.response() != null && cleanResponse.response().bodyToString().contains(result.canary)) {
                updateResult(result, r -> {
                    r.confirmed = "YES - POISONED!";
                    r.risk = "Critical";
                    r.requestResponse = cleanResponse;
                });
                api.logging().logToOutput("[!!!] Re-confirmed poisoning via " + result.inputName);
            } else {
                updateResult(result, r -> r.confirmed = "No (clean)");
            }
        } catch (Exception e) {
            api.logging().logToError("Error re-confirming: " + e.getMessage());
        }
    }

    private void updateResult(MinerResult result, java.util.function.Consumer<MinerResult> updater) {
        SwingUtilities.invokeLater(() -> {
            updater.accept(result);
            int idx = tableModel.indexOf(result);
            if (idx >= 0) tableModel.fireTableRowsUpdated(idx, idx);
        });
    }

    // ==================== ANALYSIS ====================

    private String extractSnippet(String body, String canary) {
        int index = body.indexOf(canary);
        if (index == -1) return "Canary not found in body";
        int start = Math.max(0, index - SNIPPET_CONTEXT);
        int end = Math.min(body.length(), index + canary.length() + SNIPPET_CONTEXT);
        return "..." + body.substring(start, end).replaceAll("[\\r\\n]+", " ") + "...";
    }

    private CacheStatus analyzeCacheability(HttpRequestResponse response) {
        boolean hasPositive = false;
        boolean hasNegative = false;
        String detail = "";

        for (HttpHeader h : response.response().headers()) {
            String name = h.name().toLowerCase();
            String value = h.value().toLowerCase().trim();

            if (name.equals("age") && !value.equals("0")) {
                hasPositive = true;
                detail = "Age: " + h.value();
            }
            if (name.equals("x-cache")) {
                if (value.contains("hit")) { hasPositive = true; detail = "X-Cache: HIT"; }
                else if (value.contains("miss")) { hasPositive = true; detail = "X-Cache: MISS (cacheable)"; }
            }
            if (name.equals("cf-cache-status")) {
                if (value.equals("hit") || value.equals("miss") || value.equals("expired")
                        || value.equals("stale") || value.equals("revalidated")) {
                    hasPositive = true;
                    detail = "CF-Cache-Status: " + h.value();
                }
                if (value.equals("bypass") || value.equals("dynamic")) {
                    hasNegative = true;
                }
            }
            if (name.equals("akamai-cache-status")) {
                if (value.contains("hit") || value.contains("miss") || value.contains("stale")) {
                    hasPositive = true;
                    detail = "Akamai: " + h.value();
                }
            }
            if (name.equals("x-varnish") || name.equals("x-drupal-cache") || name.equals("x-cache-hits")) {
                hasPositive = true;
                if (detail.isEmpty()) detail = name + ": " + h.value();
            }
            if (name.equals("cache-control")) {
                if (value.contains("public") || value.contains("s-maxage")) {
                    hasPositive = true;
                    if (detail.isEmpty()) detail = "Cache-Control: " + h.value();
                }
                if (value.contains("no-store") || value.contains("private") || value.contains("no-cache")) {
                    hasNegative = true;
                }
            }
            if (name.equals("pragma") && value.contains("no-cache")) {
                hasNegative = true;
            }
            if (name.equals("surrogate-control") && value.contains("no-store")) {
                hasNegative = true;
            }
        }

        if (hasPositive && !hasNegative) return new CacheStatus(true, "Yes (" + detail + ")");
        if (hasPositive)                 return new CacheStatus(true, "Maybe (conflicting: " + detail + ")");
        if (hasNegative)                 return new CacheStatus(false, "No (anti-cache headers)");
        return new CacheStatus(false, "Unknown (no cache headers)");
    }

    private String determineRisk(boolean reflected, CacheStatus cache) {
        if (reflected && cache.isCacheable) return "High";
        if (reflected) return "Medium";
        return "Info";
    }

    private void addResultSafe(MinerResult result) {
        SwingUtilities.invokeLater(() -> {
            if (tableModel.getRowCount() >= MAX_RESULTS) tableModel.removeRow(0);
            tableModel.addResult(result);
        });
    }

    // ==================== EXPORT ====================

    private void exportResults(String format) {
        if (tableModel.getRowCount() == 0) {
            JOptionPane.showMessageDialog(null, "No results to export.", "Export", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        JFileChooser chooser = new JFileChooser();
        if ("csv".equals(format)) {
            chooser.setFileFilter(new FileNameExtensionFilter("CSV Files", "csv"));
            chooser.setSelectedFile(new File("cache_miner_results.csv"));
        } else {
            chooser.setFileFilter(new FileNameExtensionFilter("JSON Files", "json"));
            chooser.setSelectedFile(new File("cache_miner_results.json"));
        }

        if (chooser.showSaveDialog(null) != JFileChooser.APPROVE_OPTION) return;

        File file = chooser.getSelectedFile();
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
            if ("csv".equals(format)) exportCsv(writer); else exportJson(writer);
            api.logging().logToOutput("[*] Results exported to: " + file.getAbsolutePath());
        } catch (IOException e) {
            api.logging().logToError("Export failed: " + e.getMessage());
            JOptionPane.showMessageDialog(null, "Export failed: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void exportCsv(BufferedWriter w) throws IOException {
        w.write("Type,Input Name,Risk,Cacheable,Confirmed,Reflection Context");
        w.newLine();
        for (int i = 0; i < tableModel.getRowCount(); i++) {
            MinerResult r = tableModel.getResult(i);
            if (r == null) continue;
            w.write(escapeCsv(r.type) + "," + escapeCsv(r.inputName) + "," +
                    escapeCsv(r.risk) + "," + escapeCsv(r.cacheable) + "," +
                    escapeCsv(r.confirmed) + "," + escapeCsv(r.snippet));
            w.newLine();
        }
    }

    private void exportJson(BufferedWriter w) throws IOException {
        w.write("[\n");
        for (int i = 0; i < tableModel.getRowCount(); i++) {
            MinerResult r = tableModel.getResult(i);
            if (r == null) continue;
            if (i > 0) w.write(",\n");
            w.write("  {\"type\":\"" + escapeJson(r.type) + "\",");
            w.write("\"input\":\"" + escapeJson(r.inputName) + "\",");
            w.write("\"risk\":\"" + escapeJson(r.risk) + "\",");
            w.write("\"cacheable\":\"" + escapeJson(r.cacheable) + "\",");
            w.write("\"confirmed\":\"" + escapeJson(r.confirmed) + "\",");
            w.write("\"context\":\"" + escapeJson(r.snippet) + "\"}");
        }
        w.write("\n]");
    }

    private String escapeCsv(String val) {
        if (val == null) return "";
        if (val.contains(",") || val.contains("\"") || val.contains("\n")) {
            return "\"" + val.replace("\"", "\"\"") + "\"";
        }
        return val;
    }

    private String escapeJson(String val) {
        if (val == null) return "";
        return val.replace("\\", "\\\\").replace("\"", "\\\"")
                  .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }

    // ==================== COLOR-CODED CELL RENDERER ====================

    static class RiskCellRenderer extends DefaultTableCellRenderer {
        private static final Color CRITICAL = new Color(180, 30, 30);
        private static final Color HIGH     = new Color(200, 70, 40);
        private static final Color MEDIUM   = new Color(200, 140, 20);
        private static final Color INFO     = new Color(70, 130, 200);

        @Override
        public Component getTableCellRendererComponent(
                JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int col) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col);

            if (isSelected) {
                setHorizontalAlignment(col == 0 || col == 3 || col == 5 ? SwingConstants.CENTER : SwingConstants.LEFT);
                return c;
            }

            String risk = "";
            Object riskVal = table.getModel().getValueAt(row, 3);
            if (riskVal != null) risk = riskVal.toString();

            Color defaultBg = table.getBackground();
            Color defaultFg = table.getForeground();
            Color altBg = blendColor(defaultBg, defaultFg, 0.05f);

            Color rowBg = row % 2 == 0 ? defaultBg : altBg;
            c.setForeground(defaultFg);
            c.setBackground(rowBg);
            setHorizontalAlignment(SwingConstants.LEFT);

            if (col == 3) {
                c.setForeground(Color.WHITE);
                switch (risk) {
                    case "Critical": c.setBackground(CRITICAL); break;
                    case "High":     c.setBackground(HIGH); break;
                    case "Medium":   c.setBackground(MEDIUM); break;
                    default:         c.setBackground(INFO); break;
                }
                setHorizontalAlignment(SwingConstants.CENTER);
            } else if (col == 5) {
                String confirmed = value != null ? value.toString() : "";
                if (confirmed.startsWith("YES")) {
                    c.setBackground(CRITICAL);
                    c.setForeground(Color.WHITE);
                }
                setHorizontalAlignment(SwingConstants.CENTER);
            } else if (col == 0) {
                setHorizontalAlignment(SwingConstants.CENTER);
            }

            return c;
        }

        private Color blendColor(Color base, Color blend, float ratio) {
            int r = (int) (base.getRed()   + (blend.getRed()   - base.getRed())   * ratio);
            int g = (int) (base.getGreen() + (blend.getGreen() - base.getGreen()) * ratio);
            int b = (int) (base.getBlue()  + (blend.getBlue()  - base.getBlue())  * ratio);
            return new Color(Math.max(0, Math.min(255, r)), Math.max(0, Math.min(255, g)), Math.max(0, Math.min(255, b)));
        }
    }

    // ==================== THREAD-SAFE TABLE MODEL ====================

    static class MinerTableModel extends AbstractTableModel {
        private final List<MinerResult> results = new ArrayList<>();
        private final String[] columns = {"#", "Type", "Input Name", "Risk", "Cacheable?", "Confirmed", "Reflection Context"};

        public synchronized void addResult(MinerResult result) {
            results.add(result);
            fireTableRowsInserted(results.size() - 1, results.size() - 1);
        }

        public synchronized void clear() {
            results.clear();
            fireTableDataChanged();
        }

        public synchronized void removeRow(int row) {
            if (row >= 0 && row < results.size()) {
                results.remove(row);
                fireTableRowsDeleted(row, row);
            }
        }

        public synchronized MinerResult getResult(int row) {
            return (row >= 0 && row < results.size()) ? results.get(row) : null;
        }

        public synchronized int indexOf(MinerResult result) {
            return results.indexOf(result);
        }

        @Override public synchronized int getRowCount() { return results.size(); }
        @Override public int getColumnCount() { return columns.length; }
        @Override public String getColumnName(int col) { return columns[col]; }

        @Override
        public synchronized Object getValueAt(int row, int col) {
            if (row < 0 || row >= results.size()) return "";
            MinerResult r = results.get(row);
            switch (col) {
                case 0: return row + 1;
                case 1: return r.type;
                case 2: return r.inputName;
                case 3: return r.risk;
                case 4: return r.cacheable;
                case 5: return r.confirmed;
                case 6: return r.snippet;
                default: return "";
            }
        }
    }

    // ==================== DATA CLASSES ====================

    static class MinerResult {
        String type;
        String inputName;
        String risk;
        String cacheable;
        String confirmed;
        String snippet;
        String canary;
        HttpRequestResponse requestResponse;

        MinerResult(String type, String inputName, String risk, String cacheable,
                    String confirmed, String snippet, HttpRequestResponse rr, String canary) {
            this.type = type;
            this.inputName = inputName;
            this.risk = risk;
            this.cacheable = cacheable;
            this.confirmed = confirmed;
            this.snippet = snippet;
            this.requestResponse = rr;
            this.canary = canary;
        }
    }

    static class MiningTask {
        final String type;
        final String name;
        MiningTask(String type, String name) { this.type = type; this.name = name; }
    }

    static class CacheStatus {
        final boolean isCacheable;
        final String label;
        CacheStatus(boolean cacheable, String label) { this.isCacheable = cacheable; this.label = label; }
    }
}
