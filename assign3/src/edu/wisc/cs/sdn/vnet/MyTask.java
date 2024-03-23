package edu.wisc.cs.sdn.vnet;

import java.util.TimerTask;

public class MyTask extends TimerTask {
    private String message;

    public MyTask(String msg){
        this.message = msg;
    }

    public void run() {
        System.out.println(this.message);
    }
}