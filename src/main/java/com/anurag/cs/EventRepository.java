package com.anurag.cs;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.*;
public interface EventRepository extends JpaRepository<WorkEvent,Long> {
    List<WorkEvent> findByKindAndWorkIdOrderByCreatedAtAscIdAsc(String kind,Long workId);
}
