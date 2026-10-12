package com.anurag.cs;
import static com.anurag.cs.ApiModels.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;
import jakarta.validation.Valid;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.nio.charset.StandardCharsets;
@RestController @RequestMapping("/api")
public class AuthController {
    private final UserRepository users;private final PasswordEncoder passwords;private final JwtService jwt;
    private final Map<String,Attempt> attempts=new ConcurrentHashMap<>();
    private record Attempt(int count,long until) {}
    public AuthController(UserRepository users,PasswordEncoder passwords,JwtService jwt){this.users=users;this.passwords=passwords;this.jwt=jwt;}
    @PostMapping("/auth/register") @ResponseStatus(HttpStatus.CREATED) @Transactional
    public AuthView register(@Valid @RequestBody Register r){AppUser u=create(r);return new AuthView(jwt.generate(u),UserView.of(u));}
    @PostMapping("/auth/login")
    public AuthView login(@Valid @RequestBody Login r) {
        String email=r.email().strip().toLowerCase(Locale.ROOT);long now=System.currentTimeMillis();
        attempts.entrySet().removeIf(e->e.getValue().until()<now);
        Attempt attempt=attempts.compute(email,(k,old)->old==null?new Attempt(1,now+900000):new Attempt(old.count()+1,old.until()));
        if(attempt.count()>8||attempts.size()>10000) throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS,"Too many sign-in attempts. Try again in 15 minutes.");
        AppUser u=users.findByEmail(email).orElse(null);
        if(u==null||!u.active||!passwords.matches(r.password(),u.passwordHash)) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,"Username or password is incorrect.");
        attempts.remove(email);return new AuthView(jwt.generate(u),UserView.of(u));
    }
    @GetMapping("/auth/me") public UserView me(@AuthenticationPrincipal Principal p){return UserView.of(users.findById(p.id()).orElseThrow());}
    @GetMapping("/admin/employees") public List<UserView> employees(){return users.findAllByOrderByCreatedAtDesc().stream().map(UserView::of).toList();}
    @PostMapping("/admin/employees") @ResponseStatus(HttpStatus.CREATED) @Transactional
    public UserView employee(@Valid @RequestBody Register r){return UserView.of(create(r));}
    @PatchMapping("/admin/employees/{id}") @Transactional
    public UserView employeeStatus(@PathVariable Long id,@Valid @RequestBody UserStatus r){
        AppUser u=users.findById(id).orElseThrow(()->new ResponseStatusException(HttpStatus.NOT_FOUND,"Employee not found."));
        if(u.role==Domain.Role.ADMIN) throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Administrator accounts cannot be disabled here.");
        u.active=r.active();return UserView.of(users.save(u));
    }
    private AppUser create(Register r){
        if(r.password().getBytes(StandardCharsets.UTF_8).length>72) throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Password must be at most 72 UTF-8 bytes.");
        String email=r.email().strip().toLowerCase(Locale.ROOT);
        if(users.findByEmail(email).isPresent()) throw new ResponseStatusException(HttpStatus.CONFLICT,"This email is already registered.");
        AppUser u=new AppUser();u.name=r.name().strip();u.email=email;u.passwordHash=passwords.encode(r.password());u.role=Domain.Role.EMPLOYEE;
        return users.save(u);
    }
}
