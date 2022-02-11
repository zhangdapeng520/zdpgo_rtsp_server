## 常用命令
发布视频流
```shell
ffmpeg -re -stream_loop -1 -i D:/data/mp4/test.mp4 -c copy -f rtsp -rtsp_transport tcp rtsp://localhost:8554/mystream
```