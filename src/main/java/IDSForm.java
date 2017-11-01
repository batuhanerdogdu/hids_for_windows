import org.apache.jena.rdf.model.Model;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;

/**
 * Created by batuh on 04/29/17.
 */
public class IDSForm extends JFrame {

    private JPanel rootPanel;
    private JButton scanMalwaresButton;
    private JButton scanNetworkPacketsButton;
    private JLabel processLabel;
    private JLabel serviceLabel;
    private JTextArea processTextArea;
    private JTextArea serviceTextArea;
    private JTabbedPane tabbedPane1;
    private JTextArea malwareTextArea;
    private JTextArea networkPacketsTextArea;
    private JTextArea sigPacketsTextArea;
    private JButton stopScanningButton;
    private JButton addMalwareToProcessesButton;
    private JButton addMalwareToServicesButton;
    private JPanel liveNetworkScanPanel;
    private JPanel malwareScanPanel;
    private JLabel malwareLabel;

    ConnectOntology co = new ConnectOntology();

    Model model;

    public IDSForm() throws Exception {
        super("Ontology and Rule Based IDS");

        setContentPane(rootPanel);
        pack();
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        processTextArea.setEditable(false);
        serviceTextArea.setEditable(false);
        malwareTextArea.setEditable(false);
        model = co.connectOnt();
        final String queryForProcessScan = ("PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>\n" +
                "PREFIX ids: <http://www.semanticweb.org/batuh/ontologies/2017/2/ids#>\n" +
                "SELECT ?y\n" +
                "WHERE{\n" +
                "?y rdf:type ids:Process.\n" +
                "?z rdf:type ids:Malware.\n" +
                "FILTER(?y = ?z)}");//gets the running processes and checks whether a malware is running as a service
        final String queryForProcessScanTypes = ("PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>\n" +
                "PREFIX ids: <http://www.semanticweb.org/batuh/ontologies/2017/2/ids#>\n" +
                "SELECT ?t\n" +
                "WHERE{\n" +
                "?y rdf:type ids:Process.\n" +
                "?z rdf:type ids:Malware.\n" +
                "?z ids:type ?t \n" +
                "FILTER(?y = ?z)}");
        final String queryForServiceScan = ("PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>\n" +
                "PREFIX ids: <http://www.semanticweb.org/batuh/ontologies/2017/2/ids#>\n" +
                "SELECT ?y\n" +
                "WHERE{\n" +
                "?y rdf:type ids:Service.\n" +
                "?z rdf:type ids:Malware.\n" +
                "FILTER(?y = ?z)}");//gets the running services and checks whether a malware is running as a service
        final String queryForServiceScanTypes = ("PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>\n" +
                "PREFIX ids: <http://www.semanticweb.org/batuh/ontologies/2017/2/ids#>\n" +
                "SELECT ?t\n" +
                "WHERE{\n" +
                "?y rdf:type ids:Service.\n" +
                "?z rdf:type ids:Malware.\n" +
                "?z ids:type ?t \n" +
                "FILTER(?y = ?z)}");
        final String queryForMalwareList = ("PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>\n" +
                "PREFIX ids: <http://www.semanticweb.org/batuh/ontologies/2017/2/ids#>\n" +
                "SELECT ?m\n" +
                "WHERE {\n" +
                "?m rdf:type ids:Malware.}\n" +
                "ORDER BY DESC (?m)");
        final String queryForMalwareTypes = ("PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>\n" +
                "PREFIX ids: <http://www.semanticweb.org/batuh/ontologies/2017/2/ids#>\n" +
                "SELECT ?t\n" +
                "WHERE {\n" +
                "?m rdf:type ids:Malware.\n" +
                "?m ids:type ?t.}\n" +
                "ORDER BY DESC (?m)");
        scanMalwaresButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                ArrayList<String> resultForProcessScan = new ArrayList<String>();
                long startTime = System.nanoTime();
                resultForProcessScan = co.executeQuery(model, queryForProcessScan, "y", "Class");
                long elapsedTime = System.nanoTime() - startTime;
                JOptionPane.showConfirmDialog(IDSForm.this, elapsedTime);

                ArrayList<String> resultForServiceScan = new ArrayList<String>();
                resultForServiceScan = co.executeQuery(model, queryForServiceScan, "y", "Class");

                ArrayList<String> resultForProcessScanTypes = new ArrayList<String>();
                resultForProcessScanTypes = co.executeQuery(model, queryForProcessScanTypes, "t", "Property");

                ArrayList<String> resultForServiceScanTypes = new ArrayList<String>();
                resultForServiceScanTypes = co.executeQuery(model, queryForServiceScanTypes, "t", "Property");

                ArrayList<String> resultsForMalwareTypes = new ArrayList<String>();
                resultsForMalwareTypes = co.executeQuery(model, queryForMalwareTypes, "t", "Property");

                ArrayList<String> resultsForMalwareList = new ArrayList<String>();
                resultsForMalwareList = co.executeQuery(model, queryForMalwareList, "m", "Class");

                System.out.println(resultsForMalwareTypes);
                System.out.println(resultsForMalwareTypes.isEmpty());

                ArrayList<String> services = co.getInstances("Service");
                ArrayList<String> process = co.getInstances("Process");

                for (int i = 0; i < process.size(); i++) {
                    processTextArea.append(process.get(i) + "\n");
                }
                for (int i = 0; i < services.size(); i++) {
                    serviceTextArea.append(services.get(i) + "\n");
                }
                for (int i = 0; i < resultsForMalwareList.size(); i++) {
                    malwareTextArea.append(resultsForMalwareTypes.get(i) + " : " + resultsForMalwareList.get(i) + "\n");
                }

                if (!resultForProcessScan.isEmpty() || !resultForServiceScan.isEmpty()) {
                    System.out.println("Service: " + resultForServiceScan);
                    System.out.println("Process: " + resultForProcessScan);
                    if (!resultForProcessScan.isEmpty())
                        JOptionPane.showMessageDialog(IDSForm.this, "Intrusion Detected in Running Processes: " + resultForProcessScanTypes.toString() + " : " + resultForProcessScan.toString());
                    if (!resultForServiceScan.isEmpty())
                        JOptionPane.showMessageDialog(IDSForm.this, "Intrusion Detected in Running Services: " + resultForServiceScanTypes.toString() + " : " + resultForServiceScan.toString());
                } else {
                    JOptionPane.showMessageDialog(IDSForm.this, "No intrusion has been detected in running services and processes.");
                }
            }
        });

        addMalwareToProcessesButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                co.addMalwareInstanceForTest("process");
            }
        });

        addMalwareToServicesButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                co.addMalwareInstanceForTest("service");
            }
        });

        scanNetworkPacketsButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                JOptionPane.showConfirmDialog(IDSForm.this, "Scan has started...");

            }
        });

        setVisible(true);
    }

    private void createUIComponents() {
        // TODO: place custom component creation code here
    }
}
