package uk.aiapplied.scotaccountclient;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

/**
 * Main application class for the ScotAccount Client.
 * This class initializes the Spring Boot application and configures component
 * scanning
 * to include both the client and JWT modules.
 */
@SpringBootApplication
@ComponentScan(basePackages = { "uk.aiapplied.scotaccountclient", "uk.aiapplied.scotaccount.jwt" })
public class ScotaccountClientApplication {

	/**
	 * Main method that starts the Spring Boot application.
	 *
	 * @param args Command line arguments passed to the application
	 */
	public static void main(String[] args) {
		SpringApplication.run(ScotaccountClientApplication.class, args);
	}

}
