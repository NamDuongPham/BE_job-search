package com.example.movieba.service;

import com.example.movieba.model.response.cv.CvRequest;
import org.springframework.core.io.Resource;
import org.springframework.web.multipart.MultipartFile;

public interface FileStorageService {

    String storeFile(MultipartFile file);

    Resource loadFileAsResource(String fileName);

    String getFileFromBase64(CvRequest cvRequest);
}
