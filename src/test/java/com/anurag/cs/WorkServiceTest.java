package com.anurag.cs;
import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import org.springframework.web.server.ResponseStatusException;
import java.util.*;
import static com.anurag.cs.ApiModels.*;
import static com.anurag.cs.Domain.*;
class WorkServiceTest {
    UserRepository users;VulnerabilityRepository findings;TaskRepository tasks;EventRepository events;WorkService service;
    AppUser owner,other,admin;Principal employeePrincipal,adminPrincipal;Vulnerability finding;AssessmentTask task;
    AppUser user(long id,Role role){AppUser u=new AppUser();u.id=id;u.name="User "+id;u.email="u"+id+"@test.example";u.role=role;return u;}
    @BeforeEach void setup(){
        users=mock(UserRepository.class);findings=mock(VulnerabilityRepository.class);tasks=mock(TaskRepository.class);events=mock(EventRepository.class);service=new WorkService(users,findings,tasks,events);
        owner=user(1,Role.EMPLOYEE);other=user(2,Role.EMPLOYEE);admin=user(3,Role.ADMIN);
        employeePrincipal=new Principal(1L,owner.email,Role.EMPLOYEE);adminPrincipal=new Principal(3L,admin.email,Role.ADMIN);
        finding=new Vulnerability();finding.id=9L;finding.version=0L;finding.reporter=other;finding.assignee=owner;finding.severity=Severity.HIGH;finding.title="Test finding";finding.asset="test.example";
        task=new AssessmentTask();task.id=7L;task.version=0L;task.assignee=owner;task.createdBy=admin;task.priority=Severity.HIGH;
        when(users.findById(1L)).thenReturn(Optional.of(owner));when(users.findById(2L)).thenReturn(Optional.of(other));when(users.findById(3L)).thenReturn(Optional.of(admin));
        when(findings.findById(9L)).thenReturn(Optional.of(finding));when(tasks.findById(7L)).thenReturn(Optional.of(task));
    }
    void status(int status,Runnable fn){assertEquals(status,assertThrows(ResponseStatusException.class,fn::run).getStatusCode().value());}
    @Test void hidesOthersFinding(){finding.assignee=other;status(403,()->service.getFinding(9L,employeePrincipal));}
    @Test void hidesOthersTask(){task.assignee=other;status(403,()->service.getTask(7L,employeePrincipal));}
    @Test void reporterCanReadButCannotChangeUnassignedFinding(){finding.reporter=owner;finding.assignee=null;assertEquals(9L,service.getFinding(9L,employeePrincipal).id());status(403,()->service.updateFinding(9L,new FindingUpdate(0L,FindingStatus.IN_PROGRESS,Severity.HIGH,null),employeePrincipal));}
    @Test void employeeCannotChangeSeverity(){status(403,()->service.updateFinding(9L,new FindingUpdate(0L,FindingStatus.IN_PROGRESS,Severity.LOW,1L),employeePrincipal));}
    @Test void employeeCannotReassign(){status(403,()->service.updateFinding(9L,new FindingUpdate(0L,FindingStatus.IN_PROGRESS,Severity.HIGH,2L),employeePrincipal));}
    @Test void employeeCannotCloseFinding(){status(400,()->service.updateFinding(9L,new FindingUpdate(0L,FindingStatus.CLOSED,Severity.HIGH,1L),employeePrincipal));}
    @Test void employeeCanStartAssignedFinding(){assertEquals(FindingStatus.IN_PROGRESS,service.updateFinding(9L,new FindingUpdate(0L,FindingStatus.IN_PROGRESS,Severity.HIGH,1L),employeePrincipal).status());verify(events).save(any());}
    @Test void adminCanCloseFinding(){assertEquals(FindingStatus.CLOSED,service.updateFinding(9L,new FindingUpdate(0L,FindingStatus.CLOSED,Severity.HIGH,1L),adminPrincipal).status());}
    @Test void rejectsStaleChanges(){status(409,()->service.updateFinding(9L,new FindingUpdate(99L,FindingStatus.IN_PROGRESS,Severity.HIGH,1L),adminPrincipal));verify(findings,never()).saveAndFlush(any());}
    @Test void cannotAssignToAdmin(){status(400,()->service.updateFinding(9L,new FindingUpdate(0L,FindingStatus.OPEN,Severity.HIGH,3L),adminPrincipal));}
    @Test void cannotAssignToDisabledEmployee(){owner.active=false;finding.assignee=null;status(400,()->service.updateFinding(9L,new FindingUpdate(0L,FindingStatus.OPEN,Severity.HIGH,1L),adminPrincipal));}
    @Test void employeeCannotCreateTask(){status(403,()->service.createTask(new TaskInput("Test","example.com",Severity.HIGH,"Authorized testing",1L,null,null),employeePrincipal));}
    @Test void employeeCannotApproveTask(){task.status=TaskStatus.IN_REVIEW;status(400,()->service.updateTask(7L,new TaskUpdate(0L,TaskStatus.COMPLETED,"Evidence",1L),employeePrincipal));}
    @Test void reviewRequiresResults(){task.status=TaskStatus.IN_PROGRESS;status(400,()->service.updateTask(7L,new TaskUpdate(0L,TaskStatus.IN_REVIEW," ",1L),employeePrincipal));}
    @Test void employeeCanSubmitResults(){task.status=TaskStatus.IN_PROGRESS;assertEquals(TaskStatus.IN_REVIEW,service.updateTask(7L,new TaskUpdate(0L,TaskStatus.IN_REVIEW,"Tested authorized scope",1L),employeePrincipal).status());}
    @Test void adminCanApproveResults(){task.status=TaskStatus.IN_REVIEW;assertEquals(TaskStatus.COMPLETED,service.updateTask(7L,new TaskUpdate(0L,TaskStatus.COMPLETED,"Tested authorized scope",1L),adminPrincipal).status());}
    @Test void protectsActivityAsWell(){finding.assignee=other;status(403,()->service.events("finding",9L,employeePrincipal));status(403,()->service.note("finding",9L,new Note("Unauthorized"),employeePrincipal));verify(events,never()).save(any());}
    @Test void missingFindingReturns404(){status(404,()->service.getFinding(123L,adminPrincipal));}
    @Test void employeeListUsesVisibilityQuery(){when(findings.visibleTo(1L)).thenReturn(List.of(finding));assertEquals(1,service.findings(employeePrincipal).size());verify(findings,never()).findAllByOrderByUpdatedAtDesc();}
}
