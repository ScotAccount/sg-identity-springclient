package scot.gov.scotaccountclient;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Main application class for the ScotAccount Client.
 * This class initializes the Spring Boot application.
 */
@SpringBootApplication
public class ScotaccountClientApplication {

    /**
     * Default constructor for ScotaccountClientApplication.
     * 
     * <p>
     * This constructor is used by Spring Boot to instantiate the main application
     * class.
     * </p>
     */
    public ScotaccountClientApplication() {
        // Default constructor required by Spring Boot
    }

    /**
     * Main method that starts the Spring Boot application.
     *
     * @param args Command line arguments passed to the application
     */
    public static void main(String[] args) {
        SpringApplication.run(ScotaccountClientApplication.class, args);
    }

}
