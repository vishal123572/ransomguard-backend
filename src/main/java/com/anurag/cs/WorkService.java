package com.anurag.cs;
import static com.anurag.cs.ApiModels.*;
import static com.anurag.cs.Domain.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;
import java.time.Instant;
import java.util.*;
@Service @Transactional
public class WorkService {
    private final UserRepository users;private final VulnerabilityRepository findings;private final TaskRepository tasks;private final EventRepository events;
    public WorkService(UserRepository u,VulnerabilityRepository v,TaskRepository t,EventRepository e){users=u;findings=v;tasks=t;events=e;}
    private ResponseStatusException forbidden(){return new ResponseStatusException(HttpStatus.FORBIDDEN,"You do not have access to this item.");}
    private ResponseStatusException bad(String text){return new ResponseStatusException(HttpStatus.BAD_REQUEST,text);}
    private AppUser actor(Principal p){return users.findById(p.id()).orElseThrow();}
    private void admin(Principal p){if(p.role()!=Role.ADMIN)throw forbidden();}
    private AppUser employee(Long id){
        if(id==null)return null;
        return users.findById(id).filter(u->u.active&&u.role==Role.EMPLOYEE).orElseThrow(()->bad("Select an active employee."));
    }
    private void version(Long expected,Long actual){if(!Objects.equals(expected,actual))throw new ResponseStatusException(HttpStatus.CONFLICT,"This item has changed. Refresh before saving.");}
    private void log(String kind,Long id,Principal p,String message){
        WorkEvent e=new WorkEvent();e.kind=kind;e.workId=id;e.actor=actor(p);e.message=message;events.save(e);
    }
    private Vulnerability finding(Long id,Principal p){
        Vulnerability v=findings.findById(id).orElseThrow(()->new ResponseStatusException(HttpStatus.NOT_FOUND,"Finding not found."));
        if(p.role()!=Role.ADMIN&&!Objects.equals(v.reporter.id,p.id())&&(v.assignee==null||!Objects.equals(v.assignee.id,p.id())))throw forbidden();
        return v;
    }
    private AssessmentTask task(Long id,Principal p){
        AssessmentTask t=tasks.findById(id).orElseThrow(()->new ResponseStatusException(HttpStatus.NOT_FOUND,"Task not found."));
        if(p.role()!=Role.ADMIN&&!Objects.equals(t.assignee.id,p.id()))throw forbidden();return t;
    }
    @Transactional(readOnly=true) public List<FindingView> findings(Principal p){
        return (p.role()==Role.ADMIN?findings.findAllByOrderByUpdatedAtDesc():findings.visibleTo(p.id())).stream().map(FindingView::of).toList();
    }
    @Transactional(readOnly=true) public FindingView getFinding(Long id,Principal p){return FindingView.of(finding(id,p));}
    public FindingView createFinding(FindingInput r,Principal p){
        Vulnerability v=new Vulnerability();v.title=r.title().strip();v.asset=r.asset().strip();v.category=r.category();v.description=r.description().strip();v.steps=r.steps();v.remediation=r.remediation();v.severity=r.severity();v.reporter=actor(p);
        findings.saveAndFlush(v);log("finding",v.id,p,"Reported this vulnerability.");return FindingView.of(v);
    }
    public FindingView updateFinding(Long id,FindingUpdate r,Principal p){
        Vulnerability v=finding(id,p);version(r.version(),v.version);
        if(p.role()!=Role.ADMIN){
            if(v.assignee==null||!Objects.equals(v.assignee.id,p.id()))throw forbidden();
            if(!Objects.equals(r.assigneeId(),v.assignee.id)||r.severity()!=v.severity)throw forbidden();
            if(v.status==FindingStatus.CLOSED||(r.status()!=v.status&&!(v.status==FindingStatus.OPEN&&r.status()==FindingStatus.IN_PROGRESS)&&!(v.status==FindingStatus.IN_PROGRESS&&r.status()==FindingStatus.RESOLVED)))throw bad("Start an open finding, then mark it resolved. An admin reviews and closes findings.");
        }
        List<String> changes=new ArrayList<>();
        Long previous=v.assignee==null?null:v.assignee.id;
        if(!Objects.equals(previous,r.assigneeId())){
            v.assignee=employee(r.assigneeId());changes.add(v.assignee==null?"Removed assignment":"Assigned to "+v.assignee.name);
        }
        if(v.status!=r.status()){changes.add("Status: "+v.status+" → "+r.status());v.status=r.status();}
        if(v.severity!=r.severity()){changes.add("Severity: "+v.severity+" → "+r.severity());v.severity=r.severity();}
        if(!changes.isEmpty()){v.updatedAt=Instant.now();findings.saveAndFlush(v);log("finding",id,p,String.join(". ",changes)+".");}
        return FindingView.of(v);
    }
    @Transactional(readOnly=true) public List<TaskView> tasks(Principal p){return (p.role()==Role.ADMIN?tasks.findAllByOrderByUpdatedAtDesc():tasks.findByAssigneeIdOrderByUpdatedAtDesc(p.id())).stream().map(TaskView::of).toList();}
    @Transactional(readOnly=true) public TaskView getTask(Long id,Principal p){return TaskView.of(task(id,p));}
    public TaskView createTask(TaskInput r,Principal p){
        admin(p);AssessmentTask t=new AssessmentTask();t.title=r.title().strip();t.asset=r.asset().strip();t.description=r.description().strip();t.priority=r.priority();t.assignee=employee(r.assigneeId());t.createdBy=actor(p);t.dueDate=r.dueDate();
        if(r.vulnerabilityId()!=null){t.vulnerability=finding(r.vulnerabilityId(),p);checkLinked(t.vulnerability,t.assignee);}
        tasks.saveAndFlush(t);log("task",t.id,p,"Created task and assigned it to "+t.assignee.name+".");return TaskView.of(t);
    }
    private void checkLinked(Vulnerability v,AppUser employee){
        if(!Objects.equals(v.reporter.id,employee.id)&&(v.assignee==null||!Objects.equals(v.assignee.id,employee.id)))throw bad("Assign the linked finding to this employee first.");
    }
    public TaskView updateTask(Long id,TaskUpdate r,Principal p){
        AssessmentTask t=task(id,p);version(r.version(),t.version);
        if(p.role()!=Role.ADMIN){
            if(r.assigneeId()!=null&&!Objects.equals(r.assigneeId(),t.assignee.id))throw forbidden();
            if(t.status==TaskStatus.COMPLETED||(r.status()!=t.status&&!(t.status==TaskStatus.TODO&&r.status()==TaskStatus.IN_PROGRESS)&&!(t.status==TaskStatus.IN_PROGRESS&&r.status()==TaskStatus.IN_REVIEW)))throw bad("Start the task, then submit your results for admin review.");
        }
        if((r.status()==TaskStatus.IN_REVIEW||r.status()==TaskStatus.COMPLETED)&&(r.result()==null||r.result().isBlank()))throw bad("Add testing results before submitting for review or completing a task.");
        List<String> changes=new ArrayList<>();
        if(p.role()==Role.ADMIN&&r.assigneeId()!=null&&!Objects.equals(t.assignee.id,r.assigneeId())){
            AppUser u=employee(r.assigneeId());if(t.vulnerability!=null)checkLinked(t.vulnerability,u);t.assignee=u;changes.add("Assigned to "+u.name);
        }
        if(t.status!=r.status()){changes.add("Status: "+t.status+" → "+r.status());t.status=r.status();}
        if(!Objects.equals(t.result,r.result())){t.result=r.result();changes.add("Updated testing results");}
        if(!changes.isEmpty()){t.updatedAt=Instant.now();tasks.saveAndFlush(t);log("task",id,p,String.join(". ",changes)+".");}
        return TaskView.of(t);
    }
    private void canView(String kind,Long id,Principal p){if(kind.equals("finding"))finding(id,p);else if(kind.equals("task"))task(id,p);else throw bad("Unknown item type.");}
    @Transactional(readOnly=true) public List<EventView> events(String kind,Long id,Principal p){canView(kind,id,p);return events.findByKindAndWorkIdOrderByCreatedAtAscIdAsc(kind,id).stream().map(EventView::of).toList();}
    public EventView note(String kind,Long id,Note r,Principal p){canView(kind,id,p);WorkEvent e=new WorkEvent();e.kind=kind;e.workId=id;e.actor=actor(p);e.message=r.message().strip();return EventView.of(events.save(e));}
}
