from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseRedirect, JsonResponse
from django.urls import reverse
from sharing.models import Shared_Resource
from django.contrib import messages

def sharing_add(request, sharing_id=0):
    template = 'sharing/sharing_detail.html'

    try:
        shared = Shared_Resource.objects.get(id=sharing_id, share_key=request.GET['key'])
    except Shared_Resource.DoesNotExist:
        shared = None

    message = ""

    if shared:
        if request.user.is_authenticated():
            if shared.redeemed and shared.matched_user_id != request.user.id:
                message = 'this invitation has already been redeemed by a different user'
            else :
                shared.redeemed = True
                shared.matched_user = request.user
                shared.save()


        type = None
        resource = None
        redirect_page = ''
        redirect_id_key = ''
        title = ''

        if shared.program_set.count() > 0:
            type = 'programs'
            title = 'Program'
            redirect_page = 'program_detail'
            redirect_id_key = 'program_id'
            resource = shared.program_set.all().first()
        elif shared.workbook_set.count() > 0:
            type = 'workbooks'
            title = 'Workbook'
            redirect_page = 'workbook_detail'
            redirect_id_key = 'workbook_id'
            resource = shared.workbook_set.all().first()
        # TODO: Add check for cohort
        if not resource:
            message = 'we were not able to find the resource'

    else:
        messages.error(request, "This shared resource has already been removed")
        if request.user.is_authenticated():
            redirect_page = 'dashboard'
        else:
            redirect_page = 'landing_page'
        return redirect(redirect_page)

    if message != "" :
        context = {
            'type': 'workbooks',
            'title': "Unknown",
            'resource': resource,
            'shared'  : shared,
            'message' : message
        }
        return render(request, template, context)

    if request.user.is_authenticated():
        return HttpResponseRedirect(reverse(redirect_page, kwargs={
            redirect_id_key: resource.id
        }))
    else:
        context = {
            'type': type,
            'title': title,
            'resource': resource,
            'shared': shared
        }
        return render(request, template, context)

@login_required
def sharing_remove(request, sharing_id=0):

    if request.POST.get('owner'):
        # The owner of the resource should also be able to remove users they shared with.
        resc = Shared_Resource.objects.get(id=sharing_id)
    else:
        # This allows users to remove resources shared with them
        resc = request.user.shared_resource_set.get(id=sharing_id)

    resc.delete()

    return JsonResponse({
        'status': 'success'
    })
