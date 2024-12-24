import java.util.concurrent.ThreadLocalRandom;

public class InfiniteApp {
    public static void main(String[] args) { 
        // Print a message to indicate the app is running
        System.out.println("The application is running. Press Ctrl+C to stop. Process Id: " + ProcessHandle.current().pid());
        long[] buffer = null;
        // Infinite loop
        while (true) { 
            try {
                int nextSize = ThreadLocalRandom.current().nextInt(10000000, 20000000);
                buffer = new long[nextSize];
                // Sleep for a while to prevent high CPU usage 
                Thread.sleep(1000); // Sleep for 1 second
                System.out.println("buffer is " + buffer.length);
            } catch (InterruptedException e) {
                // Handle exception if the thread is interrupted 
                System.out.println("Thread was interrupted: " + e.getMessage()); 
                break; // Exit the loop if interrupted 
            } 
        } 
 
        System.out.println("Application has stopped."); 
    } 
} 
