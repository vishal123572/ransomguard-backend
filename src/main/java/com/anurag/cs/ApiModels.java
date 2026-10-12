package com.anurag.cs;
import jakarta.validation.constraints.*;
import java.time.*;
public final class ApiModels {
    private ApiModels() {}
    public record Register(@NotBlank @Size(max=100) String name,@NotBlank @Email @Size(max=180) String email,@NotBlank @Size(min=10,max=72) String password) {}
    public record Login(@NotBlank @Email @Size(max=180) String email,@NotBlank @Size(max=72) String password) {}
    public record UserView(Long id,String name,String email,Domain.Role role,boolean active,Instant createdAt) {
        public static UserView of(AppUser u) { return u==null?null:new UserView(u.id,u.name,u.email,u.role,u.active,u.createdAt); }
    }
    public record AuthView(String token,UserView user) {}
    public record FindingInput(@NotBlank @Size(max=200) String title,@NotBlank @Size(max=500) String asset,@NotBlank @Size(max=60) String category,@NotNull Domain.Severity severity,@NotBlank @Size(max=10000) String description,@Size(max=10000) String steps,@Size(max=10000) String remediation) {}
    public record FindingUpdate(@NotNull Long version,@NotNull Domain.FindingStatus status,@NotNull Domain.Severity severity,Long assigneeId) {}
    public record FindingView(Long id,String title,String asset,String category,Domain.Severity severity,Domain.FindingStatus status,String description,String steps,String remediation,UserView reporter,UserView assignee,Instant createdAt,Instant updatedAt,Long version) {
        public static FindingView of(Vulnerability v) { return new FindingView(v.id,v.title,v.asset,v.category,v.severity,v.status,v.description,v.steps,v.remediation,UserView.of(v.reporter),UserView.of(v.assignee),v.createdAt,v.updatedAt,v.version); }
    }
    public record TaskInput(@NotBlank @Size(max=200) String title,@NotBlank @Size(max=500) String asset,@NotNull Domain.Severity priority,@NotBlank @Size(max=10000) String description,@NotNull Long assigneeId,Long vulnerabilityId,@FutureOrPresent LocalDate dueDate) {}
    public record TaskUpdate(@NotNull Long version,@NotNull Domain.TaskStatus status,@Size(max=10000) String result,Long assigneeId) {}
    public record TaskView(Long id,String title,String asset,Domain.Severity priority,Domain.TaskStatus status,String description,String result,UserView assignee,UserView createdBy,Long vulnerabilityId,LocalDate dueDate,Instant createdAt,Instant updatedAt,Long version) {
        public static TaskView of(AssessmentTask t) { return new TaskView(t.id,t.title,t.asset,t.priority,t.status,t.description,t.result,UserView.of(t.assignee),UserView.of(t.createdBy),t.vulnerability==null?null:t.vulnerability.id,t.dueDate,t.createdAt,t.updatedAt,t.version); }
    }
    public record Note(@NotBlank @Size(max=3500) String message) {}
    public record UserUpdate(Boolean active, @Size(min=1,max=100) String name, @Email @Size(min=1,max=180) String email) {}
    public record EventView(Long id,String message,UserView actor,Instant createdAt) {
        public static EventView of(WorkEvent e) { return new EventView(e.id,e.message,UserView.of(e.actor),e.createdAt); }
    }
    public record Principal(Long id,String email,Domain.Role role) {}
}
