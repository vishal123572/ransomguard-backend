package com.anurag.cs;
import org.springframework.boot.CommandLineRunner;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import java.util.Locale;
@Component
public class AdminBootstrap implements CommandLineRunner {
    private final UserRepository users;private final PasswordEncoder passwords;private final String email,password,name;
    public AdminBootstrap(UserRepository users,PasswordEncoder passwords,@Value("${app.admin-email:}") String email,@Value("${app.admin-password:}") String password,@Value("${app.admin-name:Workspace Admin}") String name) {
        this.users=users;this.passwords=passwords;this.email=email;this.password=password;this.name=name;
    }
    @Override @Transactional public void run(String... args) {
        if(users.existsByRole(Domain.Role.ADMIN)) return;
        if(email.isBlank()||password.isBlank()) throw new IllegalStateException("Configure ADMIN_EMAIL and ADMIN_PASSWORD for first startup.");
        if(password.length()<12||password.getBytes(java.nio.charset.StandardCharsets.UTF_8).length>72) throw new IllegalStateException("ADMIN_PASSWORD must be at least 12 characters and at most 72 UTF-8 bytes.");
        if(users.findByEmail(email.strip().toLowerCase(Locale.ROOT)).isPresent()) throw new IllegalStateException("Admin email already belongs to another account.");
        AppUser u=new AppUser();u.name=name;u.email=email.strip().toLowerCase(Locale.ROOT);u.passwordHash=passwords.encode(password);u.role=Domain.Role.ADMIN;users.save(u);
    }
}
