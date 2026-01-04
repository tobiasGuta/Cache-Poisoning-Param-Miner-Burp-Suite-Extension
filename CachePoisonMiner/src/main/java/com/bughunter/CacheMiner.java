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
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class CacheMiner implements BurpExtension, ContextMenuItemsProvider {

    private MontoyaApi api;
    private final MinerTableModel tableModel = new MinerTableModel();
    private final ExecutorService executor = Executors.newFixedThreadPool(5);
    private HttpRequestEditor requestViewer;
    private HttpResponseEditor responseViewer;
    private final Random random = new Random();

    // --- TARGET HEADERS (Potential Unkeyed Inputs) ---
    private static final List<String> MINING_HEADERS = Arrays.asList(
            "X-Forwarded-Host", "X-Host", "X-Forwarded-Server", "X-Forwarded-Scheme",
            "X-Original-URL", "X-Rewrite-URL", "X-Forwarded-Proto", "X-Forwarded-For",
            "X-Real-IP", "Fastly-Client-IP", "True-Client-IP", "X-Custom-IP-Authorization",
            "X-Frame-Options", "Origin", "Referer", "X-Forwarded-Prefix"
    );

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Cache Poisoning Miner");

        SwingUtilities.invokeLater(() -> {
            // Table Setup
            JTable table = new JTable(tableModel);
            table.setFont(new Font("SansSerif", Font.PLAIN, 12));
            table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

            // Adjust column widths for better readability
            table.getColumnModel().getColumn(0).setPreferredWidth(150); // Header
            table.getColumnModel().getColumn(1).setPreferredWidth(100); // Status
            table.getColumnModel().getColumn(2).setPreferredWidth(120); // Cacheable
            table.getColumnModel().getColumn(3).setPreferredWidth(400); // Context (Snippet)

            UserInterface ui = api.userInterface();
            requestViewer = ui.createHttpRequestEditor(EditorOptions.READ_ONLY);
            responseViewer = ui.createHttpResponseEditor(EditorOptions.READ_ONLY);

            // Listener to update Request/Response viewers on row click
            table.getSelectionModel().addListSelectionListener(e -> {
                if (!e.getValueIsAdjusting()) {
                    int selectedRow = table.getSelectedRow();
                    if (selectedRow != -1) {
                        MinerResult result = tableModel.getResult(selectedRow);
                        requestViewer.setRequest(result.requestResponse.request());
                        responseViewer.setResponse(result.requestResponse.response());
                    }
                }
            });

            // Context Menu for the Table (Delete/Clear)
            JPopupMenu popupMenu = new JPopupMenu();
            JMenuItem deleteItem = new JMenuItem("Delete Item");
            JMenuItem clearItem = new JMenuItem("Clear History");

            deleteItem.addActionListener(e -> {
                int selectedRow = table.getSelectedRow();
                if (selectedRow != -1) tableModel.removeRow(selectedRow);
            });
            clearItem.addActionListener(e -> tableModel.clear());

            popupMenu.add(deleteItem);
            popupMenu.addSeparator();
            popupMenu.add(clearItem);

            table.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseReleased(MouseEvent e) { handleContextMenu(e); }
                @Override
                public void mousePressed(MouseEvent e) { handleContextMenu(e); }
                private void handleContextMenu(MouseEvent e) {
                    if (e.isPopupTrigger()) {
                        int row = table.rowAtPoint(e.getPoint());
                        if (row != -1 && !table.isRowSelected(row)) {
                            table.setRowSelectionInterval(row, row);
                        }
                        popupMenu.show(e.getComponent(), e.getX(), e.getY());
                    }
                }
            });

            JScrollPane tableScroll = new JScrollPane(table);
            JSplitPane bottomSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestViewer.uiComponent(), responseViewer.uiComponent());
            bottomSplit.setResizeWeight(0.5);
            JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, bottomSplit);
            mainSplit.setResizeWeight(0.3);

            api.userInterface().registerSuiteTab("Cache Miner", mainSplit);
        });

        api.userInterface().registerContextMenuItemsProvider(this);
        api.logging().logToOutput("Cache Miner Loaded. Ready to hunt unkeyed inputs.");
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        if (event.messageEditorRequestResponse().isEmpty()) return null;
        JMenuItem mineItem = new JMenuItem("Mine for Unkeyed Headers");
        MessageEditorHttpRequestResponse editor = event.messageEditorRequestResponse().get();

        mineItem.addActionListener(l -> executor.submit(() -> startMining(editor.requestResponse())));

        List<Component> menuList = new ArrayList<>();
        menuList.add(mineItem);
        return menuList;
    }

    private void startMining(HttpRequestResponse baseRequestResponse) {
        HttpRequest originalRequest = baseRequestResponse.request();
        api.logging().logToOutput("[-] Starting cache mining on: " + originalRequest.url());

        // Generate a unique canary for this session
        String canary = "canary" + (10000 + random.nextInt(90000));

        for (String header : MINING_HEADERS) {
            // 1. Cache Buster: Append random parameter
            String buster = "cb=" + System.nanoTime();
            String path = originalRequest.path();
            String newPath = path.contains("?") ? path + "&" + buster : path + "?" + buster;

            // 2. Inject Header safely (Remove existing first to avoid duplicates)
            HttpRequest attackRequest = originalRequest
                    .withPath(newPath)
                    .withRemovedHeader(header)
                    .withHeader(HttpHeader.httpHeader(header, canary));

            // 3. Send Request
            try {
                HttpRequestResponse response = api.http().sendRequest(attackRequest);
                String body = response.response().bodyToString();

                // 4. Check for Reflection
                if (body.contains(canary)) {

                    boolean cacheable = isCacheable(response);
                    String snippet = extractSnippet(body, canary);

                    SwingUtilities.invokeLater(() -> tableModel.addResult(new MinerResult(
                            header,
                            "Reflected",
                            cacheable ? "YES (Potentially Poisonable)" : "No (Reflected Only)",
                            snippet,
                            response
                    )));
                    api.logging().logToOutput("[!] Found Unkeyed Input: " + header);
                }
            } catch (Exception e) {
                api.logging().logToError("Error mining " + header + ": " + e.getMessage());
            }
        }
    }

    private String extractSnippet(String body, String canary) {
        try {
            int index = body.indexOf(canary);
            if (index == -1) return "Canary not found";

            int start = Math.max(0, index - 30);
            int end = Math.min(body.length(), index + canary.length() + 30);

            return "..." + body.substring(start, end).replace("\n", " ").replace("\r", " ") + "...";
        } catch (Exception e) {
            return "Error extracting snippet";
        }
    }

    private boolean isCacheable(HttpRequestResponse response) {
        for (HttpHeader h : response.response().headers()) {
            String name = h.name().toLowerCase();
            String value = h.value().toLowerCase();

            if (name.equals("age")) return true;
            if (name.equals("x-cache") && (value.contains("hit") || value.contains("miss"))) return true;
            if (name.equals("cf-cache-status")) return true; // Cloudflare
            if (name.equals("akamai-cache-status")) return true; // Akamai
            if (name.equals("cache-control") && value.contains("public")) return true;
        }
        return false;
    }

    // --- TABLE MODEL ---
    static class MinerTableModel extends AbstractTableModel {
        private final List<MinerResult> results = new ArrayList<>();
        // Updated Columns
        private final String[] columns = {"Header", "Status", "Cacheable?", "Reflection Context"};

        public void addResult(MinerResult result) {
            results.add(result);
            fireTableRowsInserted(results.size()-1, results.size()-1);
        }

        public void clear() {
            results.clear();
            fireTableDataChanged();
        }

        public void removeRow(int row) {
            if (row >= 0 && row < results.size()) {
                results.remove(row);
                fireTableRowsDeleted(row, row);
            }
        }

        public MinerResult getResult(int row) { return results.get(row); }
        @Override public int getRowCount() { return results.size(); }
        @Override public int getColumnCount() { return columns.length; }
        @Override public String getColumnName(int col) { return columns[col]; }
        @Override public Object getValueAt(int row, int col) {
            MinerResult r = results.get(row);
            switch (col) {
                case 0: return r.header;
                case 1: return r.status;
                case 2: return r.cacheable;
                case 3: return r.snippet;
                default: return "";
            }
        }
    }

    static class MinerResult {
        String header, status, cacheable, snippet;
        HttpRequestResponse requestResponse;

        public MinerResult(String h, String s, String c, String sn, HttpRequestResponse rr) {
            this.header = h;
            this.status = s;
            this.cacheable = c;
            this.snippet = sn;
            this.requestResponse = rr;
        }
    }
}
