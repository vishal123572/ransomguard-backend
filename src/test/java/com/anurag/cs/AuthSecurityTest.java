package com.anurag.cs;
import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import org.springframework.mock.web.*;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.server.ResponseStatusException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.*;
import static com.anurag.cs.ApiModels.*;
class AuthSecurityTest {
    UserRepository users=mock(UserRepository.class);
    JwtService jwt=new JwtService("test-secret-for-unit-tests-only-01234567890123456789");
    @AfterEach void clear(){SecurityContextHolder.clearContext();}
    AppUser user(){AppUser u=new AppUser();u.id=1L;u.role=Domain.Role.EMPLOYEE;u.name="Employee";u.email="employee@example.com";u.passwordHash="NEVER_RETURN_THIS";return u;}
    @Test void unauthenticatedRequestContinuesFilterChain() throws Exception {
        var request=new MockHttpServletRequest();var response=new MockHttpServletResponse();var chain=new MockFilterChain();
        new JwtAuthenticationFilter(jwt,users).doFilter(request,response,chain);assertNotNull(chain.getRequest());
    }
    @Test void forgedTokenIsRejected() throws Exception {
        var request=new MockHttpServletRequest();request.addHeader("Authorization","Bearer invalid");var response=new MockHttpServletResponse();var chain=new MockFilterChain();
        new JwtAuthenticationFilter(jwt,users).doFilter(request,response,chain);assertEquals(401,response.getStatus());assertNull(chain.getRequest());
    }
    @Test void disabledUserTokenIsRejected() throws Exception {
        AppUser u=user();u.active=false;when(users.findById(1L)).thenReturn(Optional.of(u));
        var request=new MockHttpServletRequest();request.addHeader("Authorization","Bearer "+jwt.generate(u));var response=new MockHttpServletResponse();
        new JwtAuthenticationFilter(jwt,users).doFilter(request,response,new MockFilterChain());assertEquals(401,response.getStatus());
    }
    @Test void loadsCurrentRoleFromDatabase() throws Exception {
        AppUser u=user();String token=jwt.generate(u);u.role=Domain.Role.ADMIN;when(users.findById(1L)).thenReturn(Optional.of(u));
        var request=new MockHttpServletRequest();request.addHeader("Authorization","Bearer "+token);
        new JwtAuthenticationFilter(jwt,users).doFilter(request,new MockHttpServletResponse(),new MockFilterChain());
        Principal p=(Principal)SecurityContextHolder.getContext().getAuthentication().getPrincipal();assertEquals(Domain.Role.ADMIN,p.role());
    }
    @Test void stableSecretSurvivesRestart(){String token=jwt.generate(user());assertEquals(1L,new JwtService("test-secret-for-unit-tests-only-01234567890123456789").userId(token));}
    @Test void differentSecretCannotVerify(){String token=jwt.generate(user());assertThrows(io.jsonwebtoken.JwtException.class,()->new JwtService("a-different-secret-for-tests-only-012345678901234567").userId(token));}
    @Test void rejectsWeakSecret(){assertThrows(IllegalArgumentException.class,()->new JwtService("short"));}
    @Test void responseNeverContainsPasswordHash() throws Exception {
        String json=new ObjectMapper().findAndRegisterModules().writeValueAsString(UserView.of(user()));
        assertFalse(json.contains("password"));assertFalse(json.contains("NEVER_RETURN_THIS"));
    }
    @Test void registrationAlwaysCreatesEmployee(){
        when(users.save(any())).thenAnswer(call->{AppUser u=call.getArgument(0);u.id=1L;return u;});
        AuthController auth=new AuthController(users,new BCryptPasswordEncoder(),jwt);
        AuthView result=auth.register(new Register("Employee","EMPLOYEE@example.com","strong-password-123"));
        assertEquals(Domain.Role.EMPLOYEE,result.user().role());assertEquals("employee@example.com",result.user().email());assertNotNull(result.token());
    }
    @Test void rejectsOversizedUtf8Password(){
        AuthController auth=new AuthController(users,new BCryptPasswordEncoder(),jwt);
        assertEquals(400,assertThrows(ResponseStatusException.class,()->auth.register(new Register("Employee","e@example.com","密码".repeat(20)))).getStatusCode().value());
    }
}
