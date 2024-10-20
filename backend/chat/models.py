from django.db import models

# Create your models here.

class Chat(models.Model):
    chat_id = models.AutoField(primary_key=True)
    user_id = models.IntegerField()
    chat = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'chat'

    def __str__(self):
        return self.chat_id