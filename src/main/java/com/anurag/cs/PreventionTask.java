package com.anurag.cs;

import jakarta.persistence.*;
import java.time.Instant;
import java.time.LocalDate;

@Entity
@Table(name = "ransomware_prevention_tasks")
public class PreventionTask {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY) public Long id;
    @Column(nullable = false, length = 200) public String title;
    @Column(nullable = false, columnDefinition = "TEXT") public String instructions;
    @Column(columnDefinition = "TEXT") public String completionNotes;
    @Enumerated(EnumType.STRING) @Column(nullable = false, length = 20) public Domain.Severity priority;
    @Enumerated(EnumType.STRING) @Column(nullable = false, length = 20) public Domain.PreventionTaskStatus status = Domain.PreventionTaskStatus.TODO;
    @ManyToOne(optional = false, fetch = FetchType.EAGER) public AppUser assignedTo;
    @ManyToOne(optional = false, fetch = FetchType.EAGER) public AppUser createdBy;
    @ManyToOne(fetch = FetchType.EAGER) public FileScan relatedScan;
    public LocalDate dueDate;
    @Column(nullable = false) public Instant createdAt = Instant.now();
    @Column(nullable = false) public Instant updatedAt = Instant.now();
    @Version public Long version;
}
