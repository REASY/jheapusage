import java.util.concurrent.ThreadLocalRandom;

public class InfiniteApp {
    public static void main(String[] args) throws InterruptedException {
        ThreadLocalRandom rnd = ThreadLocalRandom.current();
        String user = System.getProperty("user.name");
        System.out.printf("Runtime is %s, user is %s\n", Runtime.version(), user);
        System.out.printf("Press Ctrl+C to stop. Process Id: %d\n", ProcessHandle.current().pid());
        long[] buffer = null;
        while (true) {
            int nextSize = rnd.nextInt(10000000, 20000000);
            buffer = new long[nextSize];
            Thread.sleep(20);
            if (nextSize % 123456 == 0) {
                System.out.println("buffer length: " + buffer.length);
            }
        }
    }
}
