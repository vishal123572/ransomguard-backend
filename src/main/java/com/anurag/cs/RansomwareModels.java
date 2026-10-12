package com.anurag.cs;

import jakarta.validation.constraints.*;
import java.time.*;
import static com.anurag.cs.ApiModels.UserView;

public final class RansomwareModels {
    private RansomwareModels() {}

    public record ScanView(Long id, String originalName, String extension, long fileSize, String sha256,
            int riskScore, Domain.ScanVerdict verdict, Domain.ScanStatus status, String detectionSummary,
            String storageStatus, UserView uploadedBy, UserView reviewedBy, Instant scannedAt, Instant updatedAt,
            Long version) {
        public static ScanView of(FileScan scan) {
            return new ScanView(scan.id, scan.originalName, scan.extension, scan.fileSize, scan.sha256,
                    scan.riskScore, scan.verdict, scan.status, scan.detectionSummary, scan.storageStatus,
                    UserView.of(scan.uploadedBy), UserView.of(scan.reviewedBy), scan.scannedAt, scan.updatedAt,
                    scan.version);
        }
    }
    public record ScanReview(@NotNull Long version, @NotNull Domain.ScanStatus status) {}
    public record TaskInput(@NotBlank @Size(max = 200) String title,
            @NotBlank @Size(max = 10000) String instructions, @NotNull Domain.Severity priority,
            @NotNull Long assigneeId, Long relatedScanId, @FutureOrPresent LocalDate dueDate) {}
    public record TaskUpdate(@NotNull Long version, @NotNull Domain.PreventionTaskStatus status,
            @Size(max = 10000) String completionNotes, Long assigneeId) {}
    public record TaskView(Long id, String title, String instructions, String completionNotes, Domain.Severity priority,
            Domain.PreventionTaskStatus status, UserView assignedTo, UserView createdBy, Long relatedScanId,
            LocalDate dueDate, Instant createdAt, Instant updatedAt, Long version) {
        public static TaskView of(PreventionTask task) {
            return new TaskView(task.id, task.title, task.instructions, task.completionNotes, task.priority,
                    task.status, UserView.of(task.assignedTo), UserView.of(task.createdBy),
                    task.relatedScan == null ? null : task.relatedScan.id, task.dueDate,
                    task.createdAt, task.updatedAt, task.version);
        }
    }
    public record EventView(Long id, String message, UserView actor, Instant createdAt) {
        public static EventView of(WorkEvent event) {
            return new EventView(event.id, event.message, UserView.of(event.actor), event.createdAt);
        }
    }
    public record Note(@NotBlank @Size(max = 3500) String message) {}
}
