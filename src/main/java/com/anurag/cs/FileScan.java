package com.anurag.cs;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "ransomware_file_scans")
public class FileScan {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY) public Long id;
    @Column(nullable = false, length = 500) public String originalName;
    @Column(nullable = false, length = 80) public String extension;
    @Column(nullable = false) public long fileSize;
    @Column(nullable = false, length = 64) public String sha256;
    @Column(nullable = false) public int riskScore;
    @Enumerated(EnumType.STRING) @Column(nullable = false, length = 20) public Domain.ScanVerdict verdict;
    @Enumerated(EnumType.STRING) @Column(nullable = false, length = 20) public Domain.ScanStatus status = Domain.ScanStatus.SCANNED;
    @Column(nullable = false, columnDefinition = "TEXT") public String detectionSummary;
    @Column(nullable = false, length = 80) public String storageStatus = "ANALYZED_NOT_RETAINED";
    @ManyToOne(optional = false, fetch = FetchType.EAGER) public AppUser uploadedBy;
    @ManyToOne(fetch = FetchType.EAGER) public AppUser reviewedBy;
    @Column(nullable = false) public Instant scannedAt = Instant.now();
    @Column(nullable = false) public Instant updatedAt = Instant.now();
    @Version public Long version;
}
