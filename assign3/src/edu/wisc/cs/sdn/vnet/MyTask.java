package edu.wisc.cs.sdn.vnet;

import java.util.TimerTask;
import edu.wisc.cs.sdn.vnet.rt.Router;

public class MyTask extends TimerTask {
    private Router router;

    public MyTask(Router router){
        this.router = router;
    }

    public void run() {
        System.out.println("Sending unsolicited response...\n" + router.toString() + "\n");
        router.sendResponse(true);
    }
}