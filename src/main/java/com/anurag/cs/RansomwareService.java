package com.anurag.cs;

import static com.anurag.cs.Domain.*;
import static com.anurag.cs.RansomwareModels.*;

import com.anurag.cs.ApiModels.Principal;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.*;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;

@Service
@Transactional
public class RansomwareService {
    private static final Set<String> HIGH_RISK_EXTENSIONS = Set.of("locked", "encrypted", "crypt", "crypto", "conti", "wannacry", "ryuk", "lockbit");
    private static final Set<String> EXECUTABLE_EXTENSIONS = Set.of("exe", "dll", "bat", "cmd", "ps1", "vbs", "js", "jar", "scr", "msi");
    private static final List<String> RANSOM_KEYWORDS = List.of("decrypt", "ransom", "recover", "readme_restore", "how_to_restore", "read_me");

    private final UserRepository users;
    private final FileScanRepository scans;
    private final PreventionTaskRepository tasks;
    private final EventRepository events;

    public RansomwareService(UserRepository users, FileScanRepository scans, PreventionTaskRepository tasks, EventRepository events) {
        this.users = users; this.scans = scans; this.tasks = tasks; this.events = events;
    }
    private ResponseStatusException forbidden() { return new ResponseStatusException(HttpStatus.FORBIDDEN, "You do not have access to this item."); }
    private ResponseStatusException bad(String message) { return new ResponseStatusException(HttpStatus.BAD_REQUEST, message); }
    private AppUser actor(Principal principal) { return users.findById(principal.id()).orElseThrow(); }
    private void admin(Principal principal) { if (principal.role() != Role.ADMIN) throw forbidden(); }
    private AppUser activeEmployee(Long id) {
        return users.findById(id).filter(user -> user.active && user.role == Role.EMPLOYEE)
            .orElseThrow(() -> bad("Select an active employee."));
    }
    private void version(Long expected, Long actual) {
        if (!Objects.equals(expected, actual)) throw new ResponseStatusException(HttpStatus.CONFLICT, "This item changed. Refresh and try again.");
    }
    private void event(String kind, Long workId, Principal actor, String message) {
        WorkEvent event = new WorkEvent(); event.kind = kind; event.workId = workId; event.actor = actor(actor); event.message = message;
        events.save(event);
    }
    private FileScan scan(Long id, Principal principal) {
        FileScan scan = scans.findById(id).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "File scan not found."));
        if (principal.role() != Role.ADMIN && !Objects.equals(scan.uploadedBy.id, principal.id())) throw forbidden();
        return scan;
    }
    private PreventionTask task(Long id, Principal principal) {
        PreventionTask task = tasks.findById(id).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Prevention task not found."));
        if (principal.role() != Role.ADMIN && !Objects.equals(task.assignedTo.id, principal.id())) throw forbidden();
        return task;
    }

    public ScanView inspect(MultipartFile file, Principal principal) {
        if (file == null || file.isEmpty()) throw bad("Choose a non-empty file to check.");
        if (file.getSize() > 10L * 1024 * 1024) throw bad("Files must be 10 MB or smaller.");
        String name = safeName(file.getOriginalFilename());
        byte[] bytes;
        try (InputStream in = file.getInputStream()) { bytes = in.readAllBytes(); } catch (IOException ex) { throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "The file could not be read."); }
        String extension = extension(name);
        Detection detection = detect(name, extension, bytes);
        FileScan scan = new FileScan();
        scan.originalName = name; scan.extension = extension; scan.fileSize = bytes.length; scan.sha256 = sha256(bytes);
        scan.riskScore = detection.score(); scan.verdict = detection.verdict(); scan.detectionSummary = detection.summary(); scan.uploadedBy = actor(principal);
        scans.saveAndFlush(scan);
        event("scan", scan.id, principal, "Uploaded a file for a safe metadata and heuristic check. The original file was not retained.");
        return ScanView.of(scan);
    }
    @Transactional(readOnly = true) public List<ScanView> scans(Principal principal) {
        return (principal.role() == Role.ADMIN ? scans.findAllByOrderByScannedAtDesc() : scans.findByUploadedByIdOrderByScannedAtDesc(principal.id()))
            .stream().map(ScanView::of).toList();
    }
    @Transactional(readOnly = true) public ScanView scanView(Long id, Principal principal) { return ScanView.of(scan(id, principal)); }
    public ScanView review(Long id, ScanReview request, Principal principal) {
        admin(principal); FileScan scan = scan(id, principal); version(request.version(), scan.version);
        if (request.status() == ScanStatus.CLOSED && scan.status != ScanStatus.QUARANTINED) throw bad("Quarantine a risky file before closing its review.");
        if (scan.status != request.status()) {
            ScanStatus before = scan.status; scan.status = request.status(); scan.reviewedBy = actor(principal); scan.updatedAt = Instant.now();
            if (request.status() == ScanStatus.QUARANTINED) scan.verdict = ScanVerdict.QUARANTINED;
            scans.saveAndFlush(scan); event("scan", scan.id, principal, "Changed review status from " + before + " to " + request.status() + ".");
        }
        return ScanView.of(scan);
    }
    @Transactional(readOnly = true) public List<TaskView> tasks(Principal principal) {
        return (principal.role() == Role.ADMIN ? tasks.findAllByOrderByUpdatedAtDesc() : tasks.findByAssignedToIdOrderByUpdatedAtDesc(principal.id()))
            .stream().map(TaskView::of).toList();
    }
    @Transactional(readOnly = true) public TaskView taskView(Long id, Principal principal) { return TaskView.of(task(id, principal)); }
    public TaskView createTask(TaskInput request, Principal principal) {
        admin(principal);
        PreventionTask task = new PreventionTask(); task.title = request.title().strip(); task.instructions = request.instructions().strip(); task.priority = request.priority();
        task.assignedTo = activeEmployee(request.assigneeId()); task.createdBy = actor(principal); task.dueDate = request.dueDate();
        if (request.relatedScanId() != null) task.relatedScan = scan(request.relatedScanId(), principal);
        tasks.saveAndFlush(task); event("task", task.id, principal, "Created a prevention task and assigned it to " + task.assignedTo.name + ".");
        return TaskView.of(task);
    }
    public TaskView updateTask(Long id, TaskUpdate request, Principal principal) {
        PreventionTask task = task(id, principal); version(request.version(), task.version);
        if (principal.role() != Role.ADMIN) {
            if (request.assigneeId() != null && !Objects.equals(request.assigneeId(), task.assignedTo.id)) throw forbidden();
            if (task.status == PreventionTaskStatus.COMPLETED || (request.status() != task.status && !isAllowedEmployeeTransition(task.status, request.status())))
                throw bad("Start the task, then submit your completion notes for review.");
        }
        if ((request.status() == PreventionTaskStatus.IN_REVIEW || request.status() == PreventionTaskStatus.COMPLETED)
                && (request.completionNotes() == null || request.completionNotes().isBlank())) throw bad("Add completion notes before submitting for review or completing a task.");
        List<String> changes = new ArrayList<>();
        if (principal.role() == Role.ADMIN && request.assigneeId() != null && !Objects.equals(task.assignedTo.id, request.assigneeId())) {
            task.assignedTo = activeEmployee(request.assigneeId()); changes.add("Assigned to " + task.assignedTo.name);
        }
        if (task.status != request.status()) { changes.add("Status: " + task.status + " → " + request.status()); task.status = request.status(); }
        if (!Objects.equals(task.completionNotes, request.completionNotes())) { task.completionNotes = request.completionNotes(); changes.add("Updated completion notes"); }
        if (!changes.isEmpty()) { task.updatedAt = Instant.now(); tasks.saveAndFlush(task); event("task", task.id, principal, String.join(". ", changes) + "."); }
        return TaskView.of(task);
    }
    private boolean isAllowedEmployeeTransition(PreventionTaskStatus from, PreventionTaskStatus to) {
        return (from == PreventionTaskStatus.TODO && to == PreventionTaskStatus.IN_PROGRESS)
            || (from == PreventionTaskStatus.IN_PROGRESS && to == PreventionTaskStatus.IN_REVIEW);
    }
    @Transactional(readOnly = true) public List<EventView> events(String kind, Long id, Principal principal) {
        if (kind.equals("scan")) scan(id, principal); else if (kind.equals("task")) task(id, principal); else throw bad("Unknown activity type.");
        return events.findByKindAndWorkIdOrderByCreatedAtAscIdAsc(kind, id).stream().map(EventView::of).toList();
    }
    public EventView note(String kind, Long id, Note request, Principal principal) {
        if (kind.equals("scan")) scan(id, principal); else if (kind.equals("task")) task(id, principal); else throw bad("Unknown activity type.");
        WorkEvent event = new WorkEvent(); event.kind = kind; event.workId = id; event.actor = actor(principal); event.message = request.message().strip();
        return EventView.of(events.save(event));
    }
    private record Detection(int score, ScanVerdict verdict, String summary) {}
    private Detection detect(String name, String extension, byte[] data) {
        String lower = name.toLowerCase(Locale.ROOT); int score = 0; List<String> signals = new ArrayList<>();
        if (HIGH_RISK_EXTENSIONS.contains(extension)) { score += 65; signals.add("The extension is frequently associated with encrypted or locked files."); }
        if (EXECUTABLE_EXTENSIONS.contains(extension)) { score += 30; signals.add("This is an executable or script file and should be handled only from a trusted source."); }
        if (lower.matches(".*\\.(pdf|docx?|xlsx?|png|jpg|zip)\\.(exe|js|vbs|cmd|bat|scr|ps1)$")) { score += 55; signals.add("A double extension can disguise an executable as a document."); }
        if (RANSOM_KEYWORDS.stream().anyMatch(lower::contains)) { score += 30; signals.add("The file name contains a recovery or ransom-note indicator."); }
        if (data.length > 0 && entropy(data) > 7.75) { score += 12; signals.add("The sampled content has high entropy; this can occur in encrypted or compressed data."); }
        score = Math.min(100, score);
        ScanVerdict verdict = score >= 70 ? ScanVerdict.HIGH_RISK : score >= 30 ? ScanVerdict.SUSPICIOUS : ScanVerdict.CLEAN;
        if (signals.isEmpty()) signals.add("No filename or content-pattern indicators were found by this heuristic check.");
        return new Detection(score, verdict, String.join(" ", signals) + " The file was not executed or retained.");
    }
    private static double entropy(byte[] bytes) {
        int[] counts = new int[256]; int length = Math.min(bytes.length, 262144);
        for (int i = 0; i < length; i++) counts[bytes[i] & 0xff]++;
        double result = 0; for (int count : counts) if (count > 0) { double p = (double) count / length; result -= p * (Math.log(p) / Math.log(2)); } return result;
    }
    private static String safeName(String value) {
        String name = value == null ? "unnamed-file" : value.replace('\\', '/');
        name = name.substring(name.lastIndexOf('/') + 1).replaceAll("[\\p{Cntrl}]", "_").strip();
        if (name.isBlank()) name = "unnamed-file"; return name.length() > 500 ? name.substring(0, 500) : name;
    }
    private static String extension(String name) {
        int index = name.lastIndexOf('.'); return index < 1 || index == name.length() - 1 ? "none" : name.substring(index + 1).toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]", "");
    }
    private static String sha256(byte[] value) {
        try { byte[] hash = MessageDigest.getInstance("SHA-256").digest(value); StringBuilder output = new StringBuilder(); for (byte b : hash) output.append(String.format("%02x", b)); return output.toString(); }
        catch (NoSuchAlgorithmException ex) { throw new IllegalStateException(ex); }
    }
}
