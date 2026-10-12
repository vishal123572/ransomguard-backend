package com.anurag.cs;
import jakarta.persistence.*;
import java.time.Instant;
import java.time.LocalDate;
@Entity @Table(name="cs_tasks")
public class AssessmentTask {
    @Id @GeneratedValue(strategy=GenerationType.IDENTITY) public Long id;
    @Column(nullable=false,length=200) public String title;
    @Column(nullable=false,length=500) public String asset;
    @Column(nullable=false,columnDefinition="TEXT") public String description;
    @Column(columnDefinition="TEXT") public String result;
    @Enumerated(EnumType.STRING) @Column(nullable=false,length=20) public Domain.Severity priority;
    @Enumerated(EnumType.STRING) @Column(nullable=false,length=20) public Domain.TaskStatus status=Domain.TaskStatus.TODO;
    @ManyToOne(optional=false,fetch=FetchType.EAGER) public AppUser assignee;
    @ManyToOne(optional=false,fetch=FetchType.EAGER) public AppUser createdBy;
    @ManyToOne(fetch=FetchType.EAGER) public Vulnerability vulnerability;
    public LocalDate dueDate;
    @Column(nullable=false) public Instant createdAt=Instant.now();
    @Column(nullable=false) public Instant updatedAt=Instant.now();
    @Version public Long version;
}
