import java.util.*;

public class CommandShell {

    public static void runShell() {
        Scanner scanner = new Scanner(System.in);
        String input;

        while (true) {
            System.out.print("vulnscan> ");
            input = scanner.nextLine().trim();

            if (input.equalsIgnoreCase("exit")) {
                System.out.println("Exiting VulnScan...");
                break;
            } else if (input.equalsIgnoreCase("help")) {
                printHelp();
            } else if (input.startsWith("scan")) {
                handleScanCommand(input);
            } else {
                System.out.println("Unknown command. Type 'help' for a list of commands.");
            }
        }

        scanner.close();
    }

    private static void handleScanCommand(String input) {
        List<String> tokens = new ArrayList<>(Arrays.asList(input.split("\\s+")));

        String scanType = null;
        String targetIP = null;
        String outputFile = null;
        boolean doHeaderCheck = false;
        boolean doSSLCheck = false;
        boolean doDirBrute = false;

        for (int i = 1; i < tokens.size(); i++) {
            String token = tokens.get(i);

            if (token.equalsIgnoreCase("basic") || token.equalsIgnoreCase("intense")) {
                scanType = token;
            } else if (token.equalsIgnoreCase("-O") && i + 1 < tokens.size()) {
                outputFile = tokens.get(i + 1);
                i++;
            } else if (token.equalsIgnoreCase("--headers")) {
                doHeaderCheck = true;
            } else if (token.equalsIgnoreCase("--ssl")) {
                doSSLCheck = true;
            } else if (token.equalsIgnoreCase("--dirs")) {
                doDirBrute = true;
            } else if (isLikelyIPorHost(token)) {
                targetIP = token;
            }
        }

        if (scanType == null || targetIP == null) {
            System.out.println("Usage: scan <target> <basic|intense> [-O <output.txt>] [--headers] [--ssl] [--dirs]");
            return;
        }

        if (scanType.equals("basic")) {
            if (outputFile != null)
                PortScanner.basicScan(targetIP, outputFile);
            else
                PortScanner.basicScan(targetIP);
        } else {
            if (outputFile != null)
                PortScanner.intenseScan(targetIP, outputFile);
            else
                PortScanner.intenseScan(targetIP);
        }

        if (doHeaderCheck) {
            PortScanner.checkHTTPHeaders("http://" + targetIP); // or https:// based on detection
        }

        if (doSSLCheck) {
            PortScanner.getSSLCertificate(targetIP, 443);
        }

        if (doDirBrute) {
            List<String> paths = List.of("admin", "login", "robots.txt", "dashboard", "config");
            PortScanner.bruteForceDirectories("http://" + targetIP, paths); // or https://
        }
    }

    private static boolean isLikelyIPorHost(String s) {
        return s.matches("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b") ||  // IPv4
               s.matches("^[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$");      // domain
    }

    private static void printHelp() {
        System.out.println("""
        Available Commands:
          scan <target> <mode> [options]
            mode: basic | intense
            options:
              -O <file>     Output results to file
              --headers     Check HTTP security headers
              --ssl         Inspect SSL certificate
              --dirs        Brute force common directories

        Examples:
          scan scanme.nmap.org basic --headers --ssl
          scan 192.168.0.1 intense -O full.txt --dirs
          scan basic scanme.nmap.org --headers -O output.txt
          exit
        """);
    }
}
