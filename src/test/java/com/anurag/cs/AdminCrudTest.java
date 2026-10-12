package com.anurag.cs;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.server.ResponseStatusException;
import com.anurag.cs.ApiModels.Principal;
import com.anurag.cs.ApiModels.UserUpdate;
import com.anurag.cs.RansomwareModels.TaskUpdate;

class AdminCrudTest {
    final UserRepository users = mock(UserRepository.class);
    final FileScanRepository scans = mock(FileScanRepository.class);
    final PreventionTaskRepository tasks = mock(PreventionTaskRepository.class);
    final EventRepository events = mock(EventRepository.class);
    final Principal admin = new Principal(1L, "admin@test.example", Domain.Role.ADMIN);
    final Principal employee = new Principal(2L, "employee@test.example", Domain.Role.EMPLOYEE);
    final AuthController auth = new AuthController(users, new BCryptPasswordEncoder(),
        new JwtService("unit-test-only-signing-secret-01234567890123456789"));
    final RansomwareService service = new RansomwareService(users, scans, tasks, events);

    AppUser user(Long id, Domain.Role role) {
        AppUser user = new AppUser(); user.id = id; user.name = "Original name";
        user.email = "original@test.example"; user.role = role;
        when(users.findById(id)).thenReturn(Optional.of(user));
        when(users.saveAndFlush(any())).thenAnswer(call -> call.getArgument(0));
        return user;
    }
    PreventionTask task() {
        PreventionTask task = new PreventionTask(); task.id = 10L; task.version = 3L;
        task.title = "Original task"; task.instructions = "Verify backups";
        task.priority = Domain.Severity.LOW; task.assignedTo = user(2L, Domain.Role.EMPLOYEE);
        task.createdBy = user(1L, Domain.Role.ADMIN);
        when(tasks.findById(task.id)).thenReturn(Optional.of(task));
        when(tasks.saveAndFlush(any())).thenAnswer(call -> call.getArgument(0));
        return task;
    }
    void status(int expected, Runnable action) {
        assertEquals(expected, assertThrows(ResponseStatusException.class, action::run).getStatusCode().value());
    }
    @Test void updatesNameAndNormalizedEmailWithoutChangingAccess() {
        AppUser user = user(2L, Domain.Role.EMPLOYEE); user.active = false;
        var result = auth.employeeStatus(2L, new UserUpdate(null, "  Updated name  ", "UPDATED@TEST.EXAMPLE"));
        assertEquals("Updated name", result.name()); assertEquals("updated@test.example", result.email());
        assertFalse(result.active()); verify(users).saveAndFlush(user);
    }
    @Test void existingEmailCanBeRetained() {
        AppUser user = user(2L, Domain.Role.EMPLOYEE);
        when(users.findByEmail(user.email)).thenReturn(Optional.of(user));
        assertEquals(user.email, auth.employeeStatus(2L, new UserUpdate(null, "Updated", user.email)).email());
    }
    @Test void duplicateEmailRejectsTheWholeUpdate() {
        AppUser user = user(2L, Domain.Role.EMPLOYEE), other = user(3L, Domain.Role.EMPLOYEE);
        when(users.findByEmail("taken@test.example")).thenReturn(Optional.of(other));
        status(409, () -> auth.employeeStatus(2L, new UserUpdate(false, "Changed", "taken@test.example")));
        assertEquals("Original name", user.name); assertTrue(user.active); verify(users, never()).saveAndFlush(any());
    }
    @Test void whitespaceNameIsRejected() {
        user(2L, Domain.Role.EMPLOYEE);
        status(400, () -> auth.employeeStatus(2L, new UserUpdate(null, "  ", null)));
        verify(users, never()).saveAndFlush(any());
    }
    @Test void emptyUpdateIsRejected() {
        user(2L, Domain.Role.EMPLOYEE);
        status(400, () -> auth.employeeStatus(2L, new UserUpdate(null, null, null)));
    }
    @Test void adminAccountCannotBeEditedOrDeleted() {
        user(1L, Domain.Role.ADMIN);
        status(400, () -> auth.employeeStatus(1L, new UserUpdate(false, "Changed", null)));
        status(400, () -> auth.deleteEmployee(1L)); verify(users, never()).delete(any());
    }
    @Test void missingEmployeeReturnsNotFound() {
        status(404, () -> auth.deleteEmployee(999L));
    }
    @Test void deletesAnUnreferencedEmployee() {
        AppUser user = user(2L, Domain.Role.EMPLOYEE); auth.deleteEmployee(2L);
        verify(users).delete(user); verify(users).flush();
    }
    @Test void linkedEmployeeDeletionReturnsConflictInsteadOfDeletingOtherRecords() {
        user(2L, Domain.Role.EMPLOYEE);
        doThrow(new DataIntegrityViolationException("Foreign key")).when(users).flush();
        status(409, () -> auth.deleteEmployee(2L));
        verifyNoInteractions(scans, tasks, events);
    }
    @Test void adminCanRenameACompletedTask() {
        PreventionTask task = task(); task.status = Domain.PreventionTaskStatus.COMPLETED; task.completionNotes = "Verified";
        var result = service.updateTask(task.id, new TaskUpdate(3L, task.status, "Verified", 2L, "  Updated task  "), admin);
        assertEquals("Updated task", result.title()); assertEquals(Domain.PreventionTaskStatus.COMPLETED, result.status());
        verify(events).save(argThat(event -> event.kind.equals("task") && event.message.contains("title")));
    }
    @Test void employeeCannotRenameTask() {
        PreventionTask task = task();
        status(403, () -> service.updateTask(task.id, new TaskUpdate(3L, task.status, null, 2L, "Unauthorized title"), employee));
        assertEquals("Original task", task.title); verify(tasks, never()).saveAndFlush(any());
    }
    @Test void staleVersionCannotRenameTask() {
        PreventionTask task = task();
        status(409, () -> service.updateTask(task.id, new TaskUpdate(1L, task.status, null, 2L, "Stale edit"), admin));
        assertEquals("Original task", task.title);
    }
    @Test void blankTaskTitleIsRejected() {
        PreventionTask task = task();
        status(400, () -> service.updateTask(task.id, new TaskUpdate(3L, task.status, null, 2L, "  "), admin));
    }
    @Test void employeesCannotDeleteEvenTheirOwnTasksOrScans() {
        status(403, () -> service.deleteTask(10L, employee));
        status(403, () -> service.deleteScan(20L, employee));
        verifyNoInteractions(scans, tasks, events);
    }
    @Test void taskDeletionRemovesOnlyItsOwnActivity() {
        PreventionTask task = task(); service.deleteTask(task.id, admin);
        verify(events).deleteByKindAndWorkId("task", task.id); verify(tasks).delete(task); verify(tasks).flush();
        verify(events, never()).deleteByKindAndWorkId(eq("scan"), any()); verifyNoInteractions(scans);
    }
    @Test void scanDeletionPreservesLinkedTasksAndLogsTheRemovedLink() {
        PreventionTask task = task(); FileScan scan = new FileScan(); scan.id = 20L;
        scan.uploadedBy = task.assignedTo; task.relatedScan = scan;
        when(scans.findById(scan.id)).thenReturn(Optional.of(scan));
        when(tasks.findByRelatedScanId(scan.id)).thenReturn(List.of(task));
        service.deleteScan(scan.id, admin);
        assertNull(task.relatedScan); verify(tasks).saveAllAndFlush(List.of(task)); verify(tasks, never()).delete(any());
        verify(events).save(argThat(event -> event.kind.equals("task") && event.workId.equals(task.id)));
        verify(events).deleteByKindAndWorkId("scan", scan.id); verify(scans).delete(scan); verify(scans).flush();
    }
    @Test void corsPermitsBrowserDeleteRequests() {
        var source = new SecurityConfig().cors("https://frontend.test.example");
        var request = new org.springframework.mock.web.MockHttpServletRequest(); request.setServletPath("/api/scans/1");
        assertTrue(source.getCorsConfiguration(request).getAllowedMethods().contains("DELETE"));
    }
}
