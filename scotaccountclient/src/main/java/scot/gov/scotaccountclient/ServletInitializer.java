package scot.gov.scotaccountclient;

import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;

/**
 * Servlet initializer for deploying the ScotAccount client application to a
 * servlet container.
 * 
 * <p>
 * This class extends SpringBootServletInitializer to support WAR deployment
 * in traditional servlet containers like Tomcat, Jetty, etc.
 * </p>
 */
public class ServletInitializer extends SpringBootServletInitializer {

    /**
     * Default constructor for ServletInitializer.
     * 
     * <p>
     * This constructor is used by the servlet container to instantiate
     * the application initializer during WAR deployment.
     * </p>
     */
    public ServletInitializer() {
        // Default constructor required by servlet container
    }

    /**
     * Configures the application when it's run in a servlet container.
     * 
     * <p>
     * This method specifies the primary sources (main application class)
     * to be used when the application is run as a WAR file.
     * </p>
     *
     * @param application the SpringApplicationBuilder to configure
     * @return the configured SpringApplicationBuilder
     */
    @Override
    protected SpringApplicationBuilder configure(SpringApplicationBuilder application) {
        return application.sources(ScotaccountClientApplication.class);
    }

}
