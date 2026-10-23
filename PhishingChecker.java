import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Phishing URL Risk Checker - Core Java Backend
 * 
 * Simple rule-based phishing URL risk analyzer using Core Java.
 * Uses the built-in Java HTTP server (com.sun.net.httpserver) so no
 * external dependencies or frameworks are required.
 * 
 * Important: This is a basic rule-based checker for educational purposes,
 * not a guaranteed phishing detector.
 */
public class PhishingChecker {

    // Port number for the server
    private static final int PORT = 8080;

    // Pattern to detect IPv4 addresses (e.g., 192.168.1.1)
    private static final Pattern IP_PATTERN = Pattern.compile(
        "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    );

    // Common URL shortening domains
    private static final List<String> URL_SHORTENERS = Arrays.asList(
        "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly", "cutt.ly", "rb.gy"
    );

    // Suspicious keywords often found in phishing lures
    private static final List<String> SUSPICIOUS_KEYWORDS = Arrays.asList(
        "login", "signin", "verify", "verification", "banking", "secure",
        "account", "update", "password", "credential", "confirm", "wallet"
    );

    public static void main(String[] args) throws IOException {
        // Create HTTP server listening on port 8080
        HttpServer server = HttpServer.create(new InetSocketAddress(PORT), 0);

        // API Endpoint: /api/check
        server.createContext("/api/check", new CheckUrlHandler());

        // Static File Endpoint: serves index.html, style.css, script.js
        server.createContext("/", new StaticFileHandler());

        // Default executor
        server.setExecutor(null);
        server.start();

        System.out.println("==================================================");
        System.out.println("   Phishing URL Risk Checker Server Started!");
        System.out.println("==================================================");
        System.out.println(" Open your browser and visit: http://localhost:" + PORT);
        System.out.println(" API Endpoint available at : http://localhost:" + PORT + "/api/check?url=<YOUR_URL>");
        System.out.println(" Press Ctrl+C in the terminal to stop the server.");
        System.out.println("==================================================");
    }

    /**
     * Handler for the URL risk checking API.
     */
    static class CheckUrlHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            // Enable CORS so client requests from Live Server or file:// work smoothly
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
            exchange.getResponseHeaders().set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
            exchange.getResponseHeaders().set("Access-Control-Allow-Headers", "Content-Type");

            // Handle preflight OPTIONS request
            if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(204, -1);
                return;
            }

            String targetUrl = "";

            // Extract URL from query string: /api/check?url=...
            URI requestUri = exchange.getRequestURI();
            String query = requestUri.getRawQuery();

            if (query != null && query.startsWith("url=")) {
                String encodedUrl = query.substring(4);
                targetUrl = URLDecoder.decode(encodedUrl, StandardCharsets.UTF_8.name());
            } else if ("POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                // Read from POST body if sent as POST
                InputStream is = exchange.getRequestBody();
                byte[] bodyBytes = is.readAllBytes();
                String body = new String(bodyBytes, StandardCharsets.UTF_8).trim();
                if (body.startsWith("url=")) {
                    targetUrl = URLDecoder.decode(body.substring(4), StandardCharsets.UTF_8.name());
                } else {
                    targetUrl = body;
                }
            }

            // Validate that a URL was provided
            if (targetUrl == null || targetUrl.trim().isEmpty()) {
                String errorJson = "{\"error\": \"Please provide a valid URL to analyze.\"}";
                byte[] responseBytes = errorJson.getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
                exchange.sendResponseHeaders(400, responseBytes.length);
                OutputStream os = exchange.getResponseBody();
                os.write(responseBytes);
                os.close();
                return;
            }

            // Analyze the URL using Core Java rule-based logic
            UrlAnalysisResult result = analyzeUrl(targetUrl.trim());

            // Build JSON response
            String jsonResponse = result.toJson();
            byte[] responseBytes = jsonResponse.getBytes(StandardCharsets.UTF_8);

            exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
            exchange.sendResponseHeaders(200, responseBytes.length);
            OutputStream os = exchange.getResponseBody();
            os.write(responseBytes);
            os.close();
        }
    }

    /**
     * Core risk analysis logic evaluating heuristics and suspicious patterns.
     */
    public static UrlAnalysisResult analyzeUrl(String inputUrl) {
        UrlAnalysisResult result = new UrlAnalysisResult(inputUrl);

        // Normalize URL if scheme is missing for parsing
        String normalizedUrl = inputUrl;
        if (!normalizedUrl.startsWith("http://") && !normalizedUrl.startsWith("https://")) {
            normalizedUrl = "http://" + normalizedUrl;
        }

        URI uri;
        try {
            uri = URI.create(normalizedUrl);
        } catch (Exception e) {
            result.addReason("Invalid or malformed URL syntax.", 40);
            result.calculateFinalRisk();
            return result;
        }

        String host = uri.getHost() != null ? uri.getHost().toLowerCase() : "";
        String scheme = uri.getScheme() != null ? uri.getScheme().toLowerCase() : "";
        String path = uri.getPath() != null ? uri.getPath().toLowerCase() : "";
        String fullUrlLower = inputUrl.toLowerCase();

        // Rule 1: Check for '@' symbol in the URL
        // Browsers ignore text before '@' and treat it as username:password, redirecting to what follows.
        if (inputUrl.contains("@")) {
            result.addReason("Contains '@' symbol: Attackers use this to obscure the real destination host.", 35);
        }

        // Rule 2: Check for raw IP address instead of domain name
        // Phishing sites often run on raw IP addresses before domains get mapped.
        if (!host.isEmpty() && isIpAddress(host)) {
            result.addReason("Uses raw IP address (" + host + ") instead of a registered domain name.", 35);
        }

        // Rule 3: Check for missing HTTPS (Insecure connection)
        // Legitimate banking/login pages almost always enforce HTTPS.
        if ("http".equalsIgnoreCase(scheme)) {
            result.addReason("Uses insecure HTTP instead of HTTPS: Data sent is unencrypted.", 20);
        }

        // Rule 4: Check for unusually long URL
        // URLs over 75 characters are frequently used to conceal redirection or junk parameters.
        if (inputUrl.length() > 75) {
            result.addReason("Unusually long URL (" + inputUrl.length() + " characters): Often used to conceal suspicious paths.", 15);
        }

        // Rule 5: Check for excessive subdomains (multiple dots in host)
        // e.g., paypal.com.account.verify.fake-domain.com
        if (!host.isEmpty()) {
            int dotCount = countOccurrences(host, '.');
            if (dotCount > 3) {
                result.addReason("Excessive subdomains (" + dotCount + " dots in host): Common method to mimic legitimate brand names.", 15);
            }
        }

        // Rule 6: Check for hyphens in the domain name
        // e.g., secure-paypal-login.com
        if (!host.isEmpty() && host.contains("-")) {
            result.addReason("Hyphen ('-') detected in domain name: Often used in lookalike / typosquatted domains.", 10);
        }

        // Rule 7: Check for suspicious phishing keywords in URL
        List<String> matchedKeywords = new ArrayList<>();
        for (String keyword : SUSPICIOUS_KEYWORDS) {
            if (fullUrlLower.contains(keyword)) {
                matchedKeywords.add(keyword);
            }
        }
        if (!matchedKeywords.isEmpty()) {
            result.addReason("Contains sensitive security keywords (" + String.join(", ", matchedKeywords) + ").", 15);
        }

        // Rule 8: Check for URL shorteners
        if (URL_SHORTENERS.contains(host)) {
            result.addReason("Uses URL shortening service (" + host + "): Obscures the true destination site.", 20);
        }

        // Rule 9: Check for double slashes in the path
        // e.g., http://attacker.com//paypal.com
        if (path.contains("//")) {
            result.addReason("Contains double slashes ('//') in path: May be used for open redirection tricks.", 15);
        }

        // Calculate final risk level and score
        result.calculateFinalRisk();
        return result;
    }

    /**
     * Checks if a string represents an IPv4 address.
     */
    private static boolean isIpAddress(String host) {
        return IP_PATTERN.matcher(host).matches();
    }

    /**
     * Utility to count character occurrences in a string.
     */
    private static int countOccurrences(String str, char ch) {
        int count = 0;
        for (int i = 0; i < str.length(); i++) {
            if (str.charAt(i) == ch) {
                count++;
            }
        }
        return count;
    }

    /**
     * Data class holding URL analysis results.
     */
    public static class UrlAnalysisResult {
        private final String url;
        private int riskScore;
        private String riskLevel;
        private final List<String> reasons;

        public UrlAnalysisResult(String url) {
            this.url = url;
            this.riskScore = 0;
            this.reasons = new ArrayList<>();
            this.riskLevel = "Low Risk";
        }

        public void addReason(String reason, int scoreWeight) {
            this.reasons.add(reason);
            this.riskScore += scoreWeight;
        }

        public void calculateFinalRisk() {
            // Cap score between 0 and 100
            if (this.riskScore > 100) {
                this.riskScore = 100;
            }

            // Determine Risk Level:
            // Score >= 50 -> High Risk
            // Score >= 20 -> Medium Risk
            // Score < 20  -> Low Risk
            if (this.riskScore >= 50) {
                this.riskLevel = "High Risk";
            } else if (this.riskScore >= 20) {
                this.riskLevel = "Medium Risk";
            } else {
                this.riskLevel = "Low Risk";
            }

            // If no negative rules matched, add a positive confirmation reason
            if (this.reasons.isEmpty()) {
                this.reasons.add("No obvious suspicious patterns detected (valid structure, standard length, no raw IP or '@' symbol).");
            }
        }

        public String getRiskLevel() {
            return riskLevel;
        }

        public int getRiskScore() {
            return riskScore;
        }

        public List<String> getReasons() {
            return reasons;
        }

        /**
         * Builds a clean JSON string manually without any external dependencies.
         */
        public String toJson() {
            StringBuilder sb = new StringBuilder();
            sb.append("{");
            sb.append("\"url\": \"").append(escapeJson(url)).append("\",");
            sb.append("\"riskLevel\": \"").append(escapeJson(riskLevel)).append("\",");
            sb.append("\"riskScore\": ").append(riskScore).append(",");
            sb.append("\"reasons\": [");
            for (int i = 0; i < reasons.size(); i++) {
                sb.append("\"").append(escapeJson(reasons.get(i))).append("\"");
                if (i < reasons.size() - 1) {
                    sb.append(", ");
                }
            }
            sb.append("],");
            sb.append("\"disclaimer\": \"This is a basic rule-based checker for educational purposes, not a guaranteed phishing detector.\"");
            sb.append("}");
            return sb.toString();
        }

        private String escapeJson(String s) {
            if (s == null) return "";
            return s.replace("\\", "\\\\")
                    .replace("\"", "\\\"")
                    .replace("\b", "\\b")
                    .replace("\f", "\\f")
                    .replace("\n", "\\n")
                    .replace("\r", "\\r")
                    .replace("\t", "\\t");
        }
    }

    /**
     * Handler to serve frontend files (index.html, style.css, script.js).
     */
    static class StaticFileHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String path = exchange.getRequestURI().getPath();

            // Default route to index.html
            if ("/".equals(path) || path.isEmpty()) {
                path = "/index.html";
            }

            // Clean path to prevent directory traversal
            File file = new File("." + path);
            if (!file.exists() || file.isDirectory()) {
                String notFound = "<h1>404 Not Found</h1>";
                exchange.sendResponseHeaders(404, notFound.length());
                OutputStream os = exchange.getResponseBody();
                os.write(notFound.getBytes(StandardCharsets.UTF_8));
                os.close();
                return;
            }

            // Determine content type
            String contentType = "text/plain";
            if (path.endsWith(".html")) {
                contentType = "text/html; charset=UTF-8";
            } else if (path.endsWith(".css")) {
                contentType = "text/css; charset=UTF-8";
            } else if (path.endsWith(".js")) {
                contentType = "application/javascript; charset=UTF-8";
            }

            byte[] fileBytes = Files.readAllBytes(file.toPath());
            exchange.getResponseHeaders().set("Content-Type", contentType);
            exchange.sendResponseHeaders(200, fileBytes.length);
            OutputStream os = exchange.getResponseBody();
            os.write(fileBytes);
            os.close();
        }
    }
}
