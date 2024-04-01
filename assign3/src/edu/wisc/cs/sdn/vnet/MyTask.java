package edu.wisc.cs.sdn.vnet;

import java.util.TimerTask;
import edu.wisc.cs.sdn.vnet.rt.Router;

public class MyTask extends TimerTask {
    private Router router;
    private int frequency;

    public MyTask(Router router, int frequency){
        this.router = router;
        this.frequency = frequency;
    }

    public void run() {
        if (frequency == 10){
            System.out.println("Sending unsolicited response...\n" + router.toString() + "\n");
            router.sendRIPPacket(Router.BROADCAST_RES, null, 0, null);
        }
        else if (frequency == 30){
            System.out.println("Update time check...\n");
            router.checkEntryTimes();
        }
        else{
            System.out.println("Error in run() function of MyTask.java");
        }
    }
}