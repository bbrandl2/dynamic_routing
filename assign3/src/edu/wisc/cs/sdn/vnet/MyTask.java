import java.util.TimerTask;
import java.util.Date;

public class MyTask extends TimerTask {
    private String message;

    public MyTask(String msg){
        this.message = msg;
    }

    public void run() {
        System.out.println(this.message);
    }
}