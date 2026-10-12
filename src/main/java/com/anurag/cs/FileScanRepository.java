package com.anurag.cs;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface FileScanRepository extends JpaRepository<FileScan, Long> {
    List<FileScan> findAllByOrderByScannedAtDesc();
    List<FileScan> findByUploadedByIdOrderByScannedAtDesc(Long userId);
}
