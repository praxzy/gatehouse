import { zodResolver } from '@hookform/resolvers/zod'
import { CheckCircle2, Copy, Plus, Save, Trash2 } from 'lucide-react'
import { useState } from 'react'
import { Controller, useFieldArray, useForm, useWatch } from 'react-hook-form'
import { toast } from 'sonner'
import { z } from 'zod'
import type { CreateApplicationResponse } from '@/api/applications'
import type { Role } from '@/api/roles'
import { RequestError } from '@/components/RequestError'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import {
  Field,
  FieldDescription,
  FieldError,
  FieldGroup,
  FieldLabel,
  FieldLegend,
  FieldSet,
} from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Sheet,
  SheetClose,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from '@/components/ui/sheet'
import { Spinner } from '@/components/ui/spinner'
import { Textarea } from '@/components/ui/textarea'
import { useCreateApplication } from '@/applications/queries'

const applicationSchema = z
  .object({
    name: z
      .string()
      .trim()
      .min(1, 'Enter an application name')
      .max(100, 'Use 100 characters or fewer'),
    description: z.string().trim().max(300, 'Use 300 characters or fewer'),
    client_type: z.enum(['public', 'confidential']),
    redirect_uris: z
      .array(
        z.object({
          value: z.string().trim().min(1, 'Enter a redirect URI'),
        }),
      )
      .min(1, 'Add at least one redirect URI')
      .max(20, 'Use no more than 20 redirect URIs'),
    access_mode: z.enum(['all_active_members', 'allowed_roles']),
    allowed_role_ids: z.array(z.string()),
  })
  .superRefine((form, context) => {
    const seen = new Set<string>()

    form.redirect_uris.forEach((entry, index) => {
      if (!isValidRedirectURI(entry.value)) {
        context.addIssue({
          code: 'custom',
          message: 'Use HTTPS, or HTTP with localhost',
          path: ['redirect_uris', index, 'value'],
        })
      }

      if (seen.has(entry.value)) {
        context.addIssue({
          code: 'custom',
          message: 'Redirect URIs must be unique',
          path: ['redirect_uris', index, 'value'],
        })
      }

      seen.add(entry.value)
    })

    if (form.access_mode === 'allowed_roles' && form.allowed_role_ids.length === 0) {
      context.addIssue({
        code: 'custom',
        message: 'Select at least one role',
        path: ['allowed_role_ids'],
      })
    }
  })

type ApplicationForm = z.infer<typeof applicationSchema>

const applicationDefaults: ApplicationForm = {
  name: '',
  description: '',
  client_type: 'confidential',
  redirect_uris: [{ value: '' }],
  access_mode: 'all_active_members',
  allowed_role_ids: [],
}

export function CreateApplicationSheet({ roles }: { roles: Role[] }) {
  const [open, setOpen] = useState(false)
  const [created, setCreated] = useState<CreateApplicationResponse | null>(null)

  const createApplication = useCreateApplication()

  const {
    control,
    register,
    handleSubmit,
    reset,
    setValue,
    formState: { errors },
  } = useForm<ApplicationForm>({
    resolver: zodResolver(applicationSchema),
    defaultValues: applicationDefaults,
  })

  const {
    fields: redirectURIFields,
    append: appendRedirectURI,
    remove: removeRedirectURI,
  } = useFieldArray({
    control,
    name: 'redirect_uris',
  })

  const accessMode = useWatch({
    control,
    name: 'access_mode',
  })

  const selectedRoleIDs =
    useWatch({
      control,
      name: 'allowed_role_ids',
    }) ?? []

  const protectedSecret = Boolean(created?.client_secret)

  function resetState() {
    setCreated(null)
    createApplication.reset()
    reset(applicationDefaults)
  }

  function changeOpen(nextOpen: boolean) {
    if (!nextOpen && protectedSecret) {
      return
    }

    setOpen(nextOpen)

    if (nextOpen) {
      resetState()
    } else {
      resetState()
    }
  }

  function toggleRole(roleID: string, selected: boolean) {
    const nextRoleIDs = selected
      ? [...selectedRoleIDs, roleID]
      : selectedRoleIDs.filter((value) => value !== roleID)

    setValue('allowed_role_ids', nextRoleIDs, {
      shouldDirty: true,
      shouldValidate: true,
    })
  }

  const submit = handleSubmit(async (form) => {
    try {
      const result = await createApplication.mutateAsync({
        name: form.name,
        description: form.description,
        client_type: form.client_type,
        redirect_uris: form.redirect_uris.map((redirectURI) => redirectURI.value),
        access_mode: form.access_mode,
        allowed_role_ids: form.access_mode === 'allowed_roles' ? form.allowed_role_ids : [],
      })

      if (result.client_secret) {
        setCreated(result)
        return
      }

      toast.success('Application created', {
        description: `${result.application.name} is ready to configure.`,
      })

      setOpen(false)
      resetState()
    } catch {
      // The request error is rendered inside the sheet.
    }
  })

  async function copyValue(value: string, label: string) {
    try {
      await navigator.clipboard.writeText(value)

      toast.success(`${label} copied`)
    } catch {
      toast.error(`Could not copy ${label.toLowerCase()}`)
    }
  }

  function finishSecretReview() {
    const applicationName = created?.application.name

    setOpen(false)
    resetState()

    toast.success('Application created', {
      description: `${applicationName} is ready to configure.`,
    })
  }

  return (
    <Sheet open={open} onOpenChange={changeOpen}>
      <SheetTrigger asChild>
        <Button type="button" className="rounded-lg">
          <Plus aria-hidden="true" />
          Create application
        </Button>
      </SheetTrigger>

      <SheetContent className="w-full sm:max-w-xl" showCloseButton={!protectedSecret}>
        {created?.client_secret ? (
          <SecretReview result={created} onCopy={copyValue} onDone={finishSecretReview} />
        ) : (
          <>
            <SheetHeader className="border-b border-border">
              <SheetTitle className="text-xl">Create application</SheetTitle>

              <SheetDescription>
                Register an application that can use Gatehouse for authentication.
              </SheetDescription>
            </SheetHeader>

            <form onSubmit={submit} noValidate className="flex min-h-0 flex-1 flex-col">
              <div className="flex-1 space-y-7 overflow-y-auto px-6 py-6">
                <RequestError error={createApplication.error} />

                <FieldGroup className="gap-5">
                  <Field data-invalid={Boolean(errors.name) || undefined}>
                    <FieldLabel htmlFor="application-name">Application name</FieldLabel>

                    <Input
                      {...register('name')}
                      id="application-name"
                      autoFocus
                      autoComplete="off"
                      maxLength={100}
                      aria-invalid={Boolean(errors.name)}
                      placeholder="Employee portal"
                      className="h-11 rounded-lg"
                    />

                    <FieldError errors={[errors.name]} />
                  </Field>

                  <Field data-invalid={Boolean(errors.description) || undefined}>
                    <FieldLabel htmlFor="application-description">Description</FieldLabel>

                    <Textarea
                      {...register('description')}
                      id="application-description"
                      maxLength={300}
                      aria-invalid={Boolean(errors.description)}
                      placeholder="Describe where this application is used."
                      className="min-h-24 resize-y rounded-lg bg-card"
                    />

                    <FieldDescription>
                      Optional. Visible to organization administrators.
                    </FieldDescription>

                    <FieldError errors={[errors.description]} />
                  </Field>

                  <Field data-invalid={Boolean(errors.client_type) || undefined}>
                    <FieldLabel htmlFor="application-client-type">Client type</FieldLabel>

                    <Controller
                      name="client_type"
                      control={control}
                      render={({ field }) => (
                        <Select value={field.value} onValueChange={field.onChange}>
                          <SelectTrigger
                            id="application-client-type"
                            className="h-11 w-full rounded-lg"
                          >
                            <SelectValue />
                          </SelectTrigger>

                          <SelectContent>
                            <SelectItem value="confidential">Confidential client</SelectItem>

                            <SelectItem value="public">Public client</SelectItem>
                          </SelectContent>
                        </Select>
                      )}
                    />

                    <FieldDescription>
                      Confidential clients receive a client secret. Browser-only and native
                      applications should be public.
                    </FieldDescription>
                  </Field>
                </FieldGroup>

                <FieldSet>
                  <div className="flex items-center justify-between gap-4">
                    <div>
                      <FieldLegend>Redirect URIs</FieldLegend>

                      <FieldDescription>
                        Gatehouse will only redirect to these exact addresses.
                      </FieldDescription>
                    </div>

                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      className="shrink-0 rounded-lg"
                      disabled={redirectURIFields.length >= 20}
                      onClick={() => appendRedirectURI({ value: '' })}
                    >
                      <Plus aria-hidden="true" />
                      Add URI
                    </Button>
                  </div>

                  <div className="space-y-3">
                    {redirectURIFields.map((field, index) => (
                      <Field
                        key={field.id}
                        data-invalid={Boolean(errors.redirect_uris?.[index]?.value) || undefined}
                      >
                        <div className="flex items-start gap-2">
                          <Input
                            {...register(`redirect_uris.${index}.value`)}
                            aria-label={`Redirect URI ${index + 1}`}
                            aria-invalid={Boolean(errors.redirect_uris?.[index]?.value)}
                            placeholder="https://app.example.com/callback"
                            className="h-11 rounded-lg font-mono text-xs"
                          />

                          <Button
                            type="button"
                            variant="outline"
                            size="icon"
                            className="size-11 shrink-0 rounded-lg"
                            disabled={redirectURIFields.length === 1}
                            onClick={() => removeRedirectURI(index)}
                            aria-label={`Remove redirect URI ${index + 1}`}
                          >
                            <Trash2 aria-hidden="true" />
                          </Button>
                        </div>

                        <FieldError errors={[errors.redirect_uris?.[index]?.value]} />
                      </Field>
                    ))}
                  </div>
                </FieldSet>

                <FieldSet>
                  <FieldLegend>Application access</FieldLegend>

                  <FieldDescription>Choose who can use this application.</FieldDescription>

                  <Controller
                    name="access_mode"
                    control={control}
                    render={({ field }) => (
                      <Select
                        value={field.value}
                        onValueChange={(value) => {
                          field.onChange(value)

                          if (value === 'all_active_members') {
                            setValue('allowed_role_ids', [], {
                              shouldDirty: true,
                              shouldValidate: true,
                            })
                          }
                        }}
                      >
                        <SelectTrigger className="h-11 w-full rounded-lg">
                          <SelectValue />
                        </SelectTrigger>

                        <SelectContent>
                          <SelectItem value="all_active_members">All active members</SelectItem>

                          <SelectItem value="allowed_roles" disabled={roles.length === 0}>
                            Selected roles
                          </SelectItem>
                        </SelectContent>
                      </Select>
                    )}
                  />

                  {accessMode === 'allowed_roles' && (
                    <div className="space-y-3">
                      {roles.map((role) => {
                        const checkboxID = `application-role-${role.role_id}`

                        return (
                          <label
                            key={role.role_id}
                            htmlFor={checkboxID}
                            className="flex cursor-pointer items-start gap-3 rounded-xl border border-border bg-card p-4 transition-colors hover:border-primary/30"
                          >
                            <Checkbox
                              id={checkboxID}
                              checked={selectedRoleIDs.includes(role.role_id)}
                              onCheckedChange={(value) => toggleRole(role.role_id, value === true)}
                              className="mt-0.5"
                            />

                            <span>
                              <span className="block text-sm font-semibold">{role.name}</span>

                              <span className="mt-1 block text-xs text-muted-foreground">
                                {role.description || 'No description provided.'}
                              </span>
                            </span>
                          </label>
                        )
                      })}

                      <FieldError errors={[errors.allowed_role_ids]} />
                    </div>
                  )}
                </FieldSet>
              </div>

              <SheetFooter className="border-t border-border">
                <SheetClose asChild>
                  <Button
                    type="button"
                    variant="outline"
                    disabled={createApplication.isPending}
                    className="rounded-lg"
                  >
                    Cancel
                  </Button>
                </SheetClose>

                <Button type="submit" disabled={createApplication.isPending} className="rounded-lg">
                  {createApplication.isPending ? (
                    <>
                      <Spinner />
                      Creating application
                    </>
                  ) : (
                    <>
                      <Save aria-hidden="true" />
                      Create application
                    </>
                  )}
                </Button>
              </SheetFooter>
            </form>
          </>
        )}
      </SheetContent>
    </Sheet>
  )
}

function SecretReview({
  result,
  onCopy,
  onDone,
}: {
  result: CreateApplicationResponse
  onCopy: (value: string, label: string) => Promise<void>
  onDone: () => void
}) {
  return (
    <>
      <SheetHeader className="border-b border-border">
        <div className="mb-2 grid size-10 place-items-center rounded-lg bg-primary/10 text-primary">
          <CheckCircle2 aria-hidden="true" />
        </div>

        <SheetTitle className="text-xl">Application created</SheetTitle>

        <SheetDescription>
          Copy the client secret now. Gatehouse will not show it again.
        </SheetDescription>
      </SheetHeader>

      <div className="flex-1 space-y-6 overflow-y-auto px-6 py-6">
        <Credential label="Client ID" value={result.application.client_id} onCopy={onCopy} />

        <Credential
          label="Client secret"
          value={result.client_secret ?? ''}
          onCopy={onCopy}
          emphasized
        />

        <p className="rounded-xl border border-gatehouse-brass/25 bg-gatehouse-brass/8 p-4 text-sm leading-6">
          Store the secret in your application’s secret manager. You cannot retrieve it after
          leaving this screen.
        </p>
      </div>

      <SheetFooter className="border-t border-border">
        <Button type="button" onClick={onDone} className="rounded-lg">
          I’ve saved the secret
        </Button>
      </SheetFooter>
    </>
  )
}

function Credential({
  label,
  value,
  onCopy,
  emphasized = false,
}: {
  label: string
  value: string
  onCopy: (value: string, label: string) => Promise<void>
  emphasized?: boolean
}) {
  return (
    <div>
      <p className="text-xs font-semibold tracking-[0.1em] text-muted-foreground uppercase">
        {label}
      </p>

      <div
        className={
          emphasized
            ? 'mt-2 flex items-center gap-2 rounded-xl border border-primary/25 bg-primary/[0.045] p-3'
            : 'mt-2 flex items-center gap-2 rounded-xl border border-border bg-muted/35 p-3'
        }
      >
        <code className="min-w-0 flex-1 text-xs break-all">{value}</code>

        <Button
          type="button"
          variant="outline"
          size="icon"
          className="shrink-0 rounded-lg"
          onClick={() => onCopy(value, label)}
          aria-label={`Copy ${label.toLowerCase()}`}
        >
          <Copy aria-hidden="true" />
        </Button>
      </div>
    </div>
  )
}

function isValidRedirectURI(value: string) {
  if (value === '' || value !== value.trim() || value.includes('#')) {
    return false
  }

  try {
    const parsed = new URL(value)

    if (parsed.username !== '' || parsed.password !== '' || parsed.hostname === '') {
      return false
    }

    return (
      parsed.protocol === 'https:' ||
      (parsed.protocol === 'http:' && parsed.hostname.toLowerCase() === 'localhost')
    )
  } catch {
    return false
  }
}
