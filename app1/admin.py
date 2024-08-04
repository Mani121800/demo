from django.contrib import admin
from .models import *

class UserProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'get_user_email', 'get_flag_display', 'batch_number')
    search_fields = ('user__username', 'user__email')
    list_filter = ('flag',)
    fields = ('user', 'flag', 'batch_number')

    def get_user_email(self, obj):
        return obj.user.email
    get_user_email.short_description = 'User Email'

    def get_flag_display(self, obj):
        return dict(UserProfile.FLAG_CHOICES).get(obj.flag, 'Unknown')
    get_flag_display.short_description = 'Flag'

    def formfield_for_choice_field(self, db_field, request, **kwargs):
        if db_field.name == 'flag':
            kwargs['choices'] = UserProfile.FLAG_CHOICES
        return super().formfield_for_choice_field(db_field, request, **kwargs)

admin.site.register(UserProfile, UserProfileAdmin)


class CourseLinksAdmin(admin.ModelAdmin):
    list_display = ( 'link', 'details', 'batch_number', 'start_date')  # Add 'batch_number' to display
    # list_filter = ('flag',)
    fields = ('link', 'details', 'batch_number', 'start_date')  # Add 'batch_number' to form fields

admin.site.register(CourseLinks, CourseLinksAdmin)

class JoinDetailsAdmin(admin.ModelAdmin):
    list_display = ('email', 'join_date')
    search_fields = ('email',)
    list_filter = ('join_date',)

admin.site.register(JoinDetails, JoinDetailsAdmin)
admin.site.register(Python_otp)
admin.site.register(Record_Landingpage)

admin.site.register(Batch)


admin.site.register(Record)
admin.site.register(WhatsAppLink_python)
admin.site.register(Python_Batch)
admin.site.register(Record_basic_python_certificates)




admin.site.register(Record_java)
admin.site.register(WhatsAppLink_java)
admin.site.register(Java_Batch)
admin.site.register(Record_basic_java_certificates)



admin.site.register(Record_community)
admin.site.register(WhatsAppLink_community)




admin.site.register(Certificate)

admin.site.register(Record_advance_python_reg)
admin.site.register(Advance_Python_Batch)
admin.site.register(Record_advance_python_certificates)

admin.site.register(Record_advance_java_reg)
admin.site.register(Advance_Java_Batch)
admin.site.register(Record_advance_java_certificates)

admin.site.register(Record_intern_reg)
admin.site.register(Intern_Batch)
admin.site.register(Record_intern_certificates)


