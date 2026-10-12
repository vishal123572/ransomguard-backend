package com.anurag.cs;
import jakarta.persistence.*;
import java.time.Instant;
@Entity @Table(name="cs_users")
public class AppUser {
    @Id @GeneratedValue(strategy=GenerationType.IDENTITY) public Long id;
    @Column(nullable=false,length=100) public String name;
    @Column(nullable=false,unique=true,length=180) public String email;
    @Column(nullable=false,length=100) public String passwordHash;
    @Enumerated(EnumType.STRING) @Column(nullable=false,length=20) public Domain.Role role;
    @Column(nullable=false) public boolean active=true;
    @Column(nullable=false) public Instant createdAt=Instant.now();
}
