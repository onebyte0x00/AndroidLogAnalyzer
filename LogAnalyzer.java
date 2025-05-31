import javax.swing.*;
import javax.swing.border.*;
import javax.swing.text.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class LogAnalyzerApp extends JFrame {
    private JTextPane logTextPane;
    private JTextPane resultTextPane;
    private File currentFile;
    private PatternInfo[] patternInfos;
    private JPanel legendPanel;

    public LogAnalyzerApp() {
        setTitle("Android Log Analyzer");
        setSize(1000, 700);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(new BorderLayout(5, 5));
        getContentPane().setBackground(new Color(45, 45, 48));

        // Initialize pattern information with colors
        initializePatterns();

        // Create components
        createUI();

        // Center on screen
        setLocationRelativeTo(null);
    }

    private void initializePatterns() {
        patternInfos = new PatternInfo[]{
                new PatternInfo("Permission Issues",
                        Pattern.compile("(?i)permission denied|avc:.*denied"),
                        new Color(220, 20, 60)), // Crimson

                new PatternInfo("Security Exceptions",
                        Pattern.compile("(?i)security exception|invalid credential"),
                        new Color(255, 140, 0)), // Dark Orange

                new PatternInfo("Root Access",
                        Pattern.compile("(?i)root access|su command"),
                        new Color(50, 205, 50)), // Lime Green

                new PatternInfo("Malware/Trojans",
                        Pattern.compile("(?i)malware|trojan|virus|backdoor"),
                        new Color(138, 43, 226)), // Violet

                new PatternInfo("Unauthorized Access",
                        Pattern.compile("(?i)unauthorized (access|attempt)|bruteforce"),
                        new Color(0, 191, 255)), // Deep Sky Blue

                new PatternInfo("Kernel Issues",
                        Pattern.compile("(?i)kernel panic|segfault|Oops\\[#\\d+\\]|Call Trace:"),
                        new Color(255, 215, 0)), // Gold

                new PatternInfo("SELinux Denials",
                        Pattern.compile("(?i)avc: denied"),
                        new Color(255, 105, 180)), // Hot Pink

                new PatternInfo("Debugging Issues",
                        Pattern.compile("(?i)debuggerd.*signal 11"),
                        new Color(64, 224, 208)), // Turquoise

                new PatternInfo("Package Issues",
                        Pattern.compile("(?i)package .* does not belong to|invalid package"),
                        new Color(147, 112, 219)) // Medium Purple
        };
    }

    private void createUI() {
        // Create a dark-themed panel for buttons
        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 10));
        topPanel.setBackground(new Color(30, 30, 32));

        // Create buttons with modern styling
        JButton browseButton = createStyledButton("Browse Log File", new Color(70, 130, 180));
        JButton analyzeButton = createStyledButton("Analyze for Suspicious Activity", new Color(46, 139, 87));
        JButton clearButton = createStyledButton("Clear Results", new Color(205, 92, 92));

        browseButton.addActionListener(this::browseLogFile);
        analyzeButton.addActionListener(this::analyzeLog);
        clearButton.addActionListener(e -> {
            resultTextPane.setText("");
            logTextPane.setText("");
            currentFile = null;
        });

        topPanel.add(browseButton);
        topPanel.add(analyzeButton);
        topPanel.add(clearButton);
        add(topPanel, BorderLayout.NORTH);

        // Create split pane for log display and results
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        splitPane.setResizeWeight(0.6);
        splitPane.setDividerSize(3);
        splitPane.setBorder(BorderFactory.createEmptyBorder());

        // Create log display area
        JPanel logPanel = new JPanel(new BorderLayout());
        logPanel.setBorder(BorderFactory.createTitledBorder("Android Log Content"));
        logTextPane = new JTextPane();
        logTextPane.setEditable(false);
        logTextPane.setBackground(new Color(25, 25, 28));
        logTextPane.setForeground(Color.LIGHT_GRAY);
        logTextPane.setFont(new Font("Monospaced", Font.PLAIN, 13));
        JScrollPane logScroll = new JScrollPane(logTextPane);
        logScroll.setBorder(BorderFactory.createEmptyBorder());
        logPanel.add(logScroll, BorderLayout.CENTER);

        // Create results display area
        JPanel resultPanel = new JPanel(new BorderLayout());
        resultPanel.setBorder(BorderFactory.createTitledBorder("Analysis Results"));
        resultTextPane = new JTextPane();
        resultTextPane.setEditable(false);
        resultTextPane.setBackground(new Color(25, 25, 28));
        resultTextPane.setForeground(Color.WHITE);
        resultTextPane.setFont(new Font("Monospaced", Font.PLAIN, 13));
        JScrollPane resultScroll = new JScrollPane(resultTextPane);
        resultScroll.setBorder(BorderFactory.createEmptyBorder());
        resultPanel.add(resultScroll, BorderLayout.CENTER);

        splitPane.setTopComponent(logPanel);
        splitPane.setBottomComponent(resultPanel);
        add(splitPane, BorderLayout.CENTER);

        // Create legend panel
        legendPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        legendPanel.setBorder(BorderFactory.createTitledBorder("Pattern Legend"));
        legendPanel.setBackground(new Color(30, 30, 32));
        legendPanel.setForeground(Color.WHITE);
        updateLegend();

        add(legendPanel, BorderLayout.SOUTH);
    }

    private JButton createStyledButton(String text, Color bgColor) {
        JButton button = new JButton(text);
        button.setBackground(bgColor);
        button.setForeground(Color.WHITE);
        button.setFocusPainted(false);
        button.setFont(new Font("Segoe UI", Font.BOLD, 12));

        // Fixed border creation: Create a compound border with line border and empty border
        Border lineBorder = BorderFactory.createLineBorder(new Color(100, 100, 100));
        Border paddingBorder = new EmptyBorder(8, 15, 8, 15);
        button.setBorder(BorderFactory.createCompoundBorder(lineBorder, paddingBorder));

        return button;
    }

    private void updateLegend() {
        legendPanel.removeAll();
        for (PatternInfo info : patternInfos) {
            JLabel label = new JLabel(info.description);
            label.setOpaque(true);
            label.setBackground(info.color);
            label.setForeground(Color.BLACK);
            label.setFont(new Font("Segoe UI", Font.BOLD, 11));

            // Create a compound border for legend items
            Border lineBorder = BorderFactory.createLineBorder(Color.DARK_GRAY);
            Border paddingBorder = new EmptyBorder(3, 8, 3, 8);
            label.setBorder(BorderFactory.createCompoundBorder(lineBorder, paddingBorder));

            legendPanel.add(label);
        }
        legendPanel.revalidate();
        legendPanel.repaint();
    }

    private void browseLogFile(ActionEvent e) {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter("Text Files", "txt"));
        if (fileChooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            currentFile = fileChooser.getSelectedFile();
            loadLogFile();
        }
    }

    private void loadLogFile() {
        if (currentFile == null) return;

        try (BufferedReader reader = new BufferedReader(new FileReader(currentFile))) {
            // Clear previous content
            logTextPane.setText("");
            resultTextPane.setText("");

            // Create a document for styled text
            StyledDocument doc = logTextPane.getStyledDocument();
            StyleContext sc = StyleContext.getDefaultStyleContext();
            Style defaultStyle = sc.getStyle(StyleContext.DEFAULT_STYLE);

            String line;
            while ((line = reader.readLine()) != null) {
                boolean matched = false;

                // Check each pattern
                for (PatternInfo info : patternInfos) {
                    Matcher m = info.pattern.matcher(line);
                    if (m.find()) {
                        // Apply style for this pattern
                        Style style = sc.addStyle(info.description, defaultStyle);
                        StyleConstants.setForeground(style, info.color);
                        StyleConstants.setBold(style, true);
                        doc.insertString(doc.getLength(), line + "\n", style);
                        matched = true;
                        break;
                    }
                }

                // If no pattern matched, use default style
                if (!matched) {
                    doc.insertString(doc.getLength(), line + "\n", defaultStyle);
                }
            }
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Error loading file: " + ex.getMessage(),
                    "File Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void analyzeLog(ActionEvent e) {
        if (currentFile == null) {
            JOptionPane.showMessageDialog(this, "No log file loaded!",
                    "Analysis Error", JOptionPane.WARNING_MESSAGE);
            return;
        }

        // Clear previous results
        resultTextPane.setText("");

        List<LogEntry> suspiciousEntries = new ArrayList<>();

        try (BufferedReader reader = new BufferedReader(new FileReader(currentFile))) {
            String line;
            int lineNum = 1;
            while ((line = reader.readLine()) != null) {
                for (PatternInfo info : patternInfos) {
                    Matcher m = info.pattern.matcher(line);
                    if (m.find()) {
                        suspiciousEntries.add(new LogEntry(lineNum, line, info));
                        break; // Avoid duplicate matches
                    }
                }
                lineNum++;
            }
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Error analyzing log: " + ex.getMessage(),
                    "Analysis Error", JOptionPane.ERROR_MESSAGE);
        }

        // Display results with color coding
        if (suspiciousEntries.isEmpty()) {
            appendToResult("No suspicious activity found!", null);
        } else {
            appendToResult("Found " + suspiciousEntries.size() + " suspicious entries:\n\n", null);
            for (LogEntry entry : suspiciousEntries) {
                appendToResult(String.format("[Line %d] ", entry.lineNum), null);
                appendToResult(entry.content + "\n", entry.patternInfo);
            }
        }
    }

    private void appendToResult(String text, PatternInfo info) {
        try {
            StyledDocument doc = resultTextPane.getStyledDocument();
            StyleContext sc = StyleContext.getDefaultStyleContext();

            if (info != null) {
                // Style for matched pattern
                Style style = sc.addStyle(info.description, null);
                StyleConstants.setForeground(style, info.color);
                StyleConstants.setBold(style, true);
                doc.insertString(doc.getLength(), text, style);
            } else {
                // Default style
                Style defaultStyle = sc.getStyle(StyleContext.DEFAULT_STYLE);
                StyleConstants.setForeground(defaultStyle, Color.LIGHT_GRAY);
                doc.insertString(doc.getLength(), text, defaultStyle);
            }
        } catch (BadLocationException ex) {
            ex.printStackTrace();
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            try {
                // Set system look and feel
                UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            } catch (Exception e) {
                e.printStackTrace();
            }

            LogAnalyzerApp app = new LogAnalyzerApp();
            app.setVisible(true);
        });
    }

    // Helper classes
    static class PatternInfo {
        String description;
        Pattern pattern;
        Color color;

        PatternInfo(String description, Pattern pattern, Color color) {
            this.description = description;
            this.pattern = pattern;
            this.color = color;
        }
    }

    static class LogEntry {
        int lineNum;
        String content;
        PatternInfo patternInfo;

        LogEntry(int lineNum, String content, PatternInfo patternInfo) {
            this.lineNum = lineNum;
            this.content = content;
            this.patternInfo = patternInfo;
        }
    }
}
