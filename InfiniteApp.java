import java.util.concurrent.ThreadLocalRandom;

public class InfiniteApp {
    public static void main(String[] args) {
        System.out.println("Runtime is: " + Runtime.version());
        System.out.println("User: " + System.getProperty("user.name"));
        System.out.println("The application is running. Press Ctrl+C to stop. Process Id: " + ProcessHandle.current().pid());
        long[] buffer = null;
        while (true) {
            try {
                int nextSize = ThreadLocalRandom.current().nextInt(10000000, 20000000);
                buffer = new long[nextSize];
                Thread.sleep(2000);
                if (nextSize % 123456 == 0) {
                    System.out.println("buffer lenght: " + buffer.length);
                }
            } catch (InterruptedException e) {
                System.out.println("Thread was interrupted: " + e.getMessage());
                break;
            }
        } 
        System.out.println("Application has stopped.");
    } 
} 
