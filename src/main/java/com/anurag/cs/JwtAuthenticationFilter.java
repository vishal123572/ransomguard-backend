package com.anurag.cs;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import java.io.IOException;
import java.util.List;
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtService jwt;
    private final UserRepository users;
    public JwtAuthenticationFilter(JwtService jwt,UserRepository users) { this.jwt=jwt;this.users=users; }
    @Override protected void doFilterInternal(HttpServletRequest req,HttpServletResponse res,FilterChain chain) throws ServletException,IOException {
        String header=req.getHeader("Authorization");
        if(header!=null) {
            try {
                if(!header.startsWith("Bearer ")) throw new IllegalArgumentException();
                AppUser user=users.findById(jwt.userId(header.substring(7))).filter(u->u.active).orElseThrow(IllegalArgumentException::new);
                var principal=new ApiModels.Principal(user.id,user.email,user.role);
                SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(principal,null,List.of(new SimpleGrantedAuthority("ROLE_"+user.role))));
            } catch(io.jsonwebtoken.JwtException | IllegalArgumentException e) {
                res.setStatus(401);res.setContentType("application/json");res.getWriter().write("{\"message\":\"Session expired or invalid. Please sign in again.\"}");return;
            }
        }
        chain.doFilter(req,res);
    }
}
