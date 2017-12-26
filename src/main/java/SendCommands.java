import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;

/**
 * Created by batuhan erdogdu on 04/09/17.
 */
public class SendCommands {//uses osquery to fetch running processes and services

    public ArrayList<String> getProcesses() throws Exception {
        ArrayList<String> commands = new ArrayList<String>();
        //commands.add("cmd");
        commands.add("osqueryi");//runs osquery
        commands.add("select name from processes;");//gets processes
        //commands.add("select name from services;");//gets services
        ProcessBuilder builder = new ProcessBuilder(commands);
        builder.redirectErrorStream(true);
        Process p = builder.start();
        BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
        String line;
        ArrayList<String> processes = new ArrayList<String>();
        while ((line = r.readLine()) != null) {
            if (!line.contains("-----") && !line.contains("+--") && !line.contains("name")){

;               processes.add(line.substring(1, 31).trim().replace(".exe", "").replace(' ', '_'));
            //System.out.println(line.substring(1,31).trim());
            }
        }
        return processes;
    }

    public ArrayList<String> getServices() throws Exception {
        ArrayList<String> commands = new ArrayList<String>();
        commands.add("osqueryi");//runs osquery
        commands.add("select name from services;");//gets services
        ProcessBuilder builder = new ProcessBuilder(commands);
        builder.redirectErrorStream(true);
        Process p = builder.start();
        BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
        String line;
        ArrayList<String> services = new ArrayList<String>();
        while ((line = r.readLine()) != null) {
            if (!line.contains("-----") && !line.contains("+--") && !line.contains("name")) {
                services.add(line.substring(1, 31).trim().replace(' ', '_'));
                //System.out.println(line.substring(1,31).trim());
            }
        }
        return services;

    }

    public String getHostIP() throws IOException {

        String command = new String();
        //commands.add("cmd");
        command = "ipconfig";//runs ipconfig
        //commands.add("select name from services;");//gets services
        ProcessBuilder builder = new ProcessBuilder(command);
        builder.redirectErrorStream(true);
        Process p = builder.start();
        BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
        String line;
        String ipAddress = new String();
        while ((line = r.readLine()) != null) {
            if (line.contains("IPv4 Address"))
                ipAddress = line.substring(38, line.length()).trim();//only for home networks for now
            //System.out.println(line.substring(1,31).trim());
        }
        return ipAddress;
    }
}

