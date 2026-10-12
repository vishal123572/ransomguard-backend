package com.anurag.cs;

import static com.anurag.cs.ApiModels.Principal;
import static com.anurag.cs.RansomwareModels.*;
import java.util.List;
import jakarta.validation.Valid;
import org.springframework.http.*;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api")
public class RansomwareController {
    private final RansomwareService service;
    public RansomwareController(RansomwareService service) { this.service = service; }
    @PostMapping(value = "/scans/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @ResponseStatus(HttpStatus.CREATED)
    public ScanView upload(@RequestParam("file") MultipartFile file, @AuthenticationPrincipal Principal principal) { return service.inspect(file, principal); }
    @GetMapping("/scans") public List<ScanView> scans(@AuthenticationPrincipal Principal principal) { return service.scans(principal); }
    @GetMapping("/scans/{id}") public ScanView scan(@PathVariable Long id, @AuthenticationPrincipal Principal principal) { return service.scanView(id, principal); }
    @PatchMapping("/scans/{id}") public ScanView review(@PathVariable Long id, @Valid @RequestBody ScanReview request, @AuthenticationPrincipal Principal principal) { return service.review(id, request, principal); }
    @GetMapping("/prevention-tasks") public List<TaskView> tasks(@AuthenticationPrincipal Principal principal) { return service.tasks(principal); }
    @GetMapping("/prevention-tasks/{id}") public TaskView task(@PathVariable Long id, @AuthenticationPrincipal Principal principal) { return service.taskView(id, principal); }
    @PostMapping("/prevention-tasks") @ResponseStatus(HttpStatus.CREATED)
    public TaskView createTask(@Valid @RequestBody TaskInput request, @AuthenticationPrincipal Principal principal) { return service.createTask(request, principal); }
    @PatchMapping("/prevention-tasks/{id}") public TaskView updateTask(@PathVariable Long id, @Valid @RequestBody TaskUpdate request, @AuthenticationPrincipal Principal principal) { return service.updateTask(id, request, principal); }
    @GetMapping("/activity/{kind:scan|task}/{id}") public List<EventView> events(@PathVariable String kind, @PathVariable Long id, @AuthenticationPrincipal Principal principal) { return service.events(kind, id, principal); }
    @PostMapping("/activity/{kind:scan|task}/{id}") @ResponseStatus(HttpStatus.CREATED)
    public EventView note(@PathVariable String kind, @PathVariable Long id, @Valid @RequestBody Note request, @AuthenticationPrincipal Principal principal) { return service.note(kind, id, request, principal); }
}
