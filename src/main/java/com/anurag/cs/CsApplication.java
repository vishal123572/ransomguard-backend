package com.anurag.cs;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
@SpringBootApplication(exclude=org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration.class)
public class CsApplication {
    public static void main(String[] args) { SpringApplication.run(CsApplication.class, args); }
}
