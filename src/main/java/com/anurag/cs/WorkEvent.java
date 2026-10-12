package com.anurag.cs;
import jakarta.persistence.*;
import java.time.Instant;
@Entity @Table(name="cs_work_events", indexes=@Index(name="cs_event_work_idx",columnList="kind,workId"))
public class WorkEvent {
    @Id @GeneratedValue(strategy=GenerationType.IDENTITY) public Long id;
    @Column(nullable=false,length=20) public String kind;
    @Column(nullable=false) public Long workId;
    @ManyToOne(optional=false,fetch=FetchType.EAGER) public AppUser actor;
    @Column(nullable=false,length=4000) public String message;
    @Column(nullable=false) public Instant createdAt=Instant.now();
}
