package com.example.movieba.controller.userpub;


import com.example.movieba.controller.BaseController;
import com.example.movieba.model.response.BaseResponse;
import com.example.movieba.service.CvService;
import com.example.movieba.service.NewsService;
import com.fasterxml.jackson.databind.ser.Serializers;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@AllArgsConstructor
@RequestMapping("/api/v1")
public class NewsController extends BaseController {
    @Autowired
    private final NewsService newsService;

    @Autowired
    private final CvService cvService;

    @GetMapping("/public-news")
    ResponseEntity<BaseResponse> getAllNews(@RequestParam int offset, @RequestParam int limit){
        PageRequest pageRequest = PageRequest.of(offset,limit);
        return success(newsService.getNewLimit(pageRequest));
    }

    @GetMapping("/news")
    ResponseEntity<BaseResponse> getNews(){
        return success(newsService.filterNews());
    }

    @GetMapping("/new/{idNew}")
    ResponseEntity<BaseResponse> getNewsByIdNew(@PathVariable long idNew){
        return success(newsService.getNews(idNew));
    }

    @GetMapping("/total-find-news")
    ResponseEntity<BaseResponse> getTotalNews(){
        return success(newsService.totalFindNews());
    }

    @GetMapping("/search")
    ResponseEntity<BaseResponse> searchNews(@RequestParam String keyWord, @RequestParam Long locationId, @RequestParam Long careerId,
                                            @RequestParam Integer sort){
        return success(newsService.findAllByKeyWord(keyWord,locationId,careerId,keyWord,keyWord,keyWord,keyWord,sort));
    }



}
