package com.example.movieba.service.Impl;

import com.example.movieba.exception.FileStorageException;
import com.example.movieba.exception.MyFileNotFoundException;
import com.example.movieba.model.response.cv.CvRequest;
import com.example.movieba.properties.FileStorageProperties;
import com.example.movieba.service.FileStorageService;
import com.example.movieba.utils.RandomString;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.Base64;

@Service
@AllArgsConstructor
public class FileStorageServiceImpl implements FileStorageService {

    private final Path fileStorageLocation;



    @Autowired
    public FileStorageServiceImpl(FileStorageProperties fileStorageProperties) {
        this.fileStorageLocation = Paths.get(fileStorageProperties.getUploadDir()).toAbsolutePath().normalize();
        try {
            Files.createDirectories(this.fileStorageLocation);
        } catch (Exception ex) {
            throw new FileStorageException("Could not create the directory where the uploaded files will be stored.", ex);
        }
    }

    @Override
    public String storeFile(MultipartFile file) {
        String fileName = StringUtils.cleanPath(file.getOriginalFilename());

        try {
            // Check if the file's name contains invalid characters
            if(fileName.contains("..")) {
                throw new FileStorageException("Sorry! Filename contains invalid path sequence " + fileName);
            }

            // Copy file to the target location (Replacing existing file with the same name)
            Path targetLocation = this.fileStorageLocation.resolve(fileName);
            Files.copy(file.getInputStream(), targetLocation, StandardCopyOption.REPLACE_EXISTING);

            return fileName;
        } catch (IOException ex) {
            throw new FileStorageException("Could not store file " + fileName + ". Please try again!", ex);
        }
    }

    @Override
    public Resource loadFileAsResource(String fileName) {
        try {
            Path filePath = this.fileStorageLocation.resolve(fileName).normalize();
            Resource resource = new UrlResource(filePath.toUri());
            if(resource.exists()) {
                return resource;
            } else {
                throw new MyFileNotFoundException("File not found " + fileName);
            }
        } catch (MalformedURLException ex) {
            throw new MyFileNotFoundException("File not found " + fileName, ex);
        }
    }

    @Override
    public String getFileFromBase64(CvRequest cvRequest) {
        RandomString randomString = new RandomString();
        File file = new File(this.fileStorageLocation +"\\"+ cvRequest.getAuthor() +"_"+randomString.nextString() + ".pdf");
        try(FileOutputStream fos = new FileOutputStream(file);){
            byte[] decoder= Base64.getDecoder().decode(cvRequest.getData());
            fos.write(decoder);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return file.getName();
    }


}
