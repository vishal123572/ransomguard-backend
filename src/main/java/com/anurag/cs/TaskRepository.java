package com.anurag.cs;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.*;
public interface TaskRepository extends JpaRepository<AssessmentTask,Long> {
    List<AssessmentTask> findAllByOrderByUpdatedAtDesc();
    List<AssessmentTask> findByAssigneeIdOrderByUpdatedAtDesc(Long userId);
}
