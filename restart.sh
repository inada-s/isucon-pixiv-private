sudo rm /var/log/nginx/access.log 
sudo systemctl restart mysql
sudo systemctl restart nginx
sudo systemctl restart isu-go
