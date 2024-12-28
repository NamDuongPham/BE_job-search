package com.example.movieba.controller;


import com.example.movieba.model.request.news.NewsRequest;
import com.example.movieba.model.response.BaseResponse;
import com.example.movieba.service.NewsService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@AllArgsConstructor
@RequestMapping("/api/v2")
public class NewController extends BaseController {
    private final NewsService newsService;

    @PostMapping("/create-news/{idCom}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN') OR hasAuthority('ROLE_USER') OR hasAuthority('ROLE_STAFF')")
    ResponseEntity<BaseResponse> createNew(@PathVariable long idCom, @RequestBody NewsRequest newsRequest){
        newsService.addNew(idCom,newsRequest);
        return success();
    }

    @PutMapping("/update-news/{idNew}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN') OR hasAuthority('ROLE_STAFF')")
    ResponseEntity<BaseResponse> updateNew(@PathVariable long idNew, @RequestBody NewsRequest newsRequest){
        newsService.updateNew(idNew, newsRequest);
        return success();
    }


    @PutMapping("/change-status/{idNew}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN') OR hasAuthority('ROLE_STAFF')")
    ResponseEntity<BaseResponse> changeStatus(@PathVariable long idNew, @RequestParam String status){
        newsService.acceptNew(idNew, status);
        return success();
    }


    @GetMapping("/info-new/{idNew}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN') OR hasAuthority('ROLE_USER') OR hasAuthority('ROLE_STAFF')")
    ResponseEntity<BaseResponse> infoNew(@PathVariable long idNew){

        return success(newsService.getNews(idNew));
    }

    @GetMapping("/all-new-company/{id}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN') OR hasAuthority('ROLE_USER') OR hasAuthority('ROLE_STAFF')")
    ResponseEntity<BaseResponse> getAll(@PathVariable long id){
        return success(newsService.getAllNewsByIds(id));
    }


    @GetMapping("/all-new")
    @PreAuthorize("hasAuthority('ROLE_ADMIN') OR hasAuthority('ROLE_USER') OR hasAuthority('ROLE_STAFF')")
    ResponseEntity<BaseResponse> allNew(){
        return success(newsService.getAllNews());
    }


    @GetMapping("/total-news")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    ResponseEntity<BaseResponse> totalNews(){
        return success(newsService.total());
    }

    @GetMapping("/apply/{idNew}")
    @PreAuthorize("hasAuthority('ROLE_USER')")
    ResponseEntity<BaseResponse> applyJob(@PathVariable long idNew, @RequestParam long idCv, HttpServletRequest request){
        newsService.applyJob(idCv,idNew, request);
        return success();
    }





}
