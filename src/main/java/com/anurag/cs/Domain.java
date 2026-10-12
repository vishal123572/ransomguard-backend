package com.anurag.cs;
public final class Domain {
    private Domain() {}
    public enum Role { ADMIN, EMPLOYEE }
    public enum ScanVerdict { CLEAN, SUSPICIOUS, HIGH_RISK, QUARANTINED }
    public enum ScanStatus { SCANNED, QUARANTINED, CLOSED }
    public enum PreventionTaskStatus { TODO, IN_PROGRESS, IN_REVIEW, COMPLETED }
    public enum Severity { CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL }
    public enum FindingStatus { OPEN, IN_PROGRESS, RESOLVED, CLOSED }
    public enum TaskStatus { TODO, IN_PROGRESS, IN_REVIEW, COMPLETED }
}
