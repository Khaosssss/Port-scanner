import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;


public class PortScanner {

    private static final Map<Integer, String> KNOWN_SERVICES = new LinkedHashMap<>() {{
        put(21, "FTP");
        put(22, "SSH");
        put(23, "Telnet");
        put(25, "SMTP");
        put(53, "DNS");
        put(80, "HTTP");
        put(110, "POP3");
        put(135, "RPC");
        put(139, "NetBIOS");
        put(143, "IMAP");
        put(443, "HTTPS");
        put(445, "SMB");
        put(993, "IMAPS");
        put(995, "POP3S");
        put(3306, "MySQL");
        put(3389, "RDP");
        put(8080, "HTTP-Alt");
    }};

    public static void resolveTarget(String target, PrintWriter writer) {
    try {
        InetAddress inetAddress = InetAddress.getByName(target);
        String resolvedIP = inetAddress.getHostAddress();
        String resolvedHost = inetAddress.getCanonicalHostName();

        // Print and optionally write
        if (target.equals(resolvedIP)) {
            System.out.println("Target IP: " + resolvedIP);
            System.out.println("Resolved Hostname: " + resolvedHost);
            if (writer != null) {
                writer.println("Target IP: " + resolvedIP);
                writer.println("Resolved Hostname: " + resolvedHost);
            }
        } else {
            System.out.println("Target Domain: " + target);
            System.out.println("Resolved IP: " + resolvedIP);
            if (writer != null) {
                writer.println("Target Domain: " + target);
                writer.println("Resolved IP: " + resolvedIP);
            }
        }

    } catch (UnknownHostException e) {
        System.out.println("[-] Failed to resolve: " + target);
        if (writer != null) writer.println("[-] Failed to resolve: " + target);
    }
}


    public static void grabBanner(String ip, int port) {
    try (Socket socket = new Socket(ip, port)) {
        socket.setSoTimeout(2000);
        InputStream in = socket.getInputStream();
        byte[] buffer = new byte[4096];
        int read = in.read(buffer);
        if (read > 0) {
            String banner = new String(buffer, 0, read);
            System.out.printf(" [*] Port %d banner: %s\n", port, banner.trim());
        }
        } catch (IOException e) {
        // No banner or timeout
        }
    }

    public static void checkHTTPHeaders(String targetUrl) {
        try {
            URI uri = URI.create(targetUrl);
            URL url = uri.toURL();

            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.connect();

            Map<String, List<String>> headers = connection.getHeaderFields();
            System.out.println("\n[HTTP Security Header Check]");
            List<String> requiredHeaders = List.of(
                "Content-Security-Policy",
                "Strict-Transport-Security",
                "X-Content-Type-Options",
                "X-Frame-Options"
            );

            for (String header : requiredHeaders) {
                if (headers.containsKey(header)) {
                    System.out.println(" [+] " + header + " is PRESENT");
                } else {
                    System.out.println(" [-] " + header + " is MISSING");
                }
            }

            // 🍪 Cookie Security Check
            System.out.println("\n[Cookie Security Check]");
            List<String> cookies = headers.get("Set-Cookie");
            if (cookies != null) {
                for (String cookie : cookies) {
                    System.out.println(" Cookie: " + cookie.split(";")[0]); // Show cookie name=value

                    boolean hasSecure = cookie.toLowerCase().contains("secure");
                    boolean hasHttpOnly = cookie.toLowerCase().contains("httponly");

                    if (!hasSecure) {
                        System.out.println("  [-] Missing Secure flag");
                    } else {
                        System.out.println("  [+] Secure flag present");
                    }

                    if (!hasHttpOnly) {
                        System.out.println("  [-] Missing HttpOnly flag");
                    } else {
                        System.out.println("  [+] HttpOnly flag present");
                    }
                }
            } else {
                System.out.println(" [-] No cookies set by server");
            }

        } catch (Exception e) {
            System.out.println("[-] HTTP header check failed: " + e.getMessage());
        }
    }


    public static void bruteForceDirectories(String baseUrl, List<String> wordlist) {
        System.out.println("\n[Directory Brute Force]");
        for (String path : wordlist) {
            try {
                URI uri = URI.create(baseUrl + "/" + path);
                URL url = uri.toURL();

                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("GET");
                conn.connect();

                int code = conn.getResponseCode();
                if (code == 200 || code == 301 || code == 403) {
                    System.out.println(" [+] Found: /" + path + " (" + code + ")");
                }

            } catch (IOException ignored) {
            }
        }
    }

    public static void getSSLCertificate(String host, int port) {
        try {
            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            SSLSocket socket = (SSLSocket) factory.createSocket(host, port);
            socket.startHandshake();

            SSLSession session = socket.getSession();
            Certificate[] certs = session.getPeerCertificates();
            X509Certificate cert = (X509Certificate) certs[0];

            System.out.println("\n[SSL Certificate]");
            System.out.println(" Subject: " + cert.getSubjectX500Principal());
            System.out.println(" Issuer: " + cert.getIssuerX500Principal());
            System.out.println(" Expiry: " + cert.getNotAfter());

        } catch (Exception e) {
            System.out.println("[-] Failed to fetch SSL certificate: " + e.getMessage());
        }
    }




    private static void scanPort(String ip, int port, String service, PrintWriter writer) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(ip, port), 200);
            String message = String.format(" [+] Port %d (%s) is OPEN", port, service);
            System.out.println(message);
            if (writer != null) writer.println(message);
        } catch (IOException ignored) {
            // Port is closed or filtered
        }
    }

    public static void basicScan(String ip) {
        basicScan(ip, null);
    }

    public static void basicScan(String ip, String outputFileName) {
        PrintWriter writer = null;
        if (outputFileName != null) {
            try {
                writer = new PrintWriter(new FileWriter(outputFileName));
                writer.println("Basic Scan Report for " + ip);
                writer.println("==============================");
            } catch (IOException e) {
                System.out.println("[-] Error writing to file: " + outputFileName);
            }
        }
        resolveTarget(ip, writer);


        for (Map.Entry<Integer, String> entry : KNOWN_SERVICES.entrySet()) {
            int port = entry.getKey();
            String service = entry.getValue();
            scanPort(ip, port, service, writer);
        }

        if (writer != null) {
            writer.close();
            System.out.println("\n[+] Scan results saved to: " + outputFileName);
        }
    }

    public static void intenseScan(String ip) {
        intenseScan(ip, null);
    }

    public static void intenseScan(String ip, String outputFileName) {
        PrintWriter writer = null;
        if (outputFileName != null) {
            try {
                writer = new PrintWriter(new FileWriter(outputFileName));
                writer.println("Intense Scan Report for " + ip);
                writer.println("==============================");
            } catch (IOException e) {
                System.out.println("[-] Error writing to file: " + outputFileName);
            }
        }
        resolveTarget(ip, writer);


        for (int port = 1; port <= 1024; port++) {
            String service = KNOWN_SERVICES.getOrDefault(port, "unknown");
            scanPort(ip, port, service, writer);
        }

        if (writer != null) {
            writer.close();
            System.out.println("\n[+] Scan results saved to: " + outputFileName);
        }
    }
}
