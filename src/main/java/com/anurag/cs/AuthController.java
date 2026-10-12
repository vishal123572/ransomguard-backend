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
import org.springframework.dao.DataIntegrityViolationException;
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
    public UserView employeeStatus(@PathVariable Long id,@Valid @RequestBody UserUpdate r){
        AppUser u=users.findById(id).orElseThrow(()->new ResponseStatusException(HttpStatus.NOT_FOUND,"Employee not found."));
        if(u.role==Domain.Role.ADMIN) throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Administrator accounts cannot be changed here.");
        if(r.active()==null&&r.name()==null&&r.email()==null) throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Provide a name, email, or access status to update.");
        String name=r.name()==null?null:r.name().strip();
        String email=r.email()==null?null:r.email().strip().toLowerCase(Locale.ROOT);
        if((name!=null&&name.isEmpty())||(email!=null&&email.isEmpty())) throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Name and email cannot be blank.");
        if(email!=null&&users.findByEmail(email).filter(other->!Objects.equals(other.id,id)).isPresent())
            throw new ResponseStatusException(HttpStatus.CONFLICT,"This email is already registered.");
        if(name!=null)u.name=name;
        if(email!=null)u.email=email;
        if(r.active()!=null)u.active=r.active();
        return UserView.of(users.saveAndFlush(u));
    }
    @DeleteMapping("/admin/employees/{id}") @ResponseStatus(HttpStatus.NO_CONTENT) @Transactional
    public void deleteEmployee(@PathVariable Long id){
        AppUser u=users.findById(id).orElseThrow(()->new ResponseStatusException(HttpStatus.NOT_FOUND,"Employee not found."));
        if(u.role==Domain.Role.ADMIN)throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Administrator accounts cannot be deleted here.");
        try { users.delete(u);users.flush(); }
        catch(DataIntegrityViolationException ex){throw new ResponseStatusException(HttpStatus.CONFLICT,"This employee still has linked records or activity. Reassign or remove those records, or deactivate the employee instead.");}
    }
    private AppUser create(Register r){
        if(r.password().getBytes(StandardCharsets.UTF_8).length>72) throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Password must be at most 72 UTF-8 bytes.");
        String email=r.email().strip().toLowerCase(Locale.ROOT);
        if(users.findByEmail(email).isPresent()) throw new ResponseStatusException(HttpStatus.CONFLICT,"This email is already registered.");
        AppUser u=new AppUser();u.name=r.name().strip();u.email=email;u.passwordHash=passwords.encode(r.password());u.role=Domain.Role.EMPLOYEE;
        return users.save(u);
    }
}
