package com.anurag.cs;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface PreventionTaskRepository extends JpaRepository<PreventionTask, Long> {
    List<PreventionTask> findAllByOrderByUpdatedAtDesc();
    List<PreventionTask> findByAssignedToIdOrderByUpdatedAtDesc(Long userId);
}
