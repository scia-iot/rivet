import { Check, ChevronsUpDown } from 'lucide-react'
import { useState } from 'react'

import { Button } from '@/components/ui/button'
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from '@/components/ui/command'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'
import { cn } from '@/lib/utils'

export interface EntitySelectOption {
  value: string
  label: string
  keywords?: string[]
  disabled?: boolean
}

interface EntitySelectProps {
  id?: string
  'aria-describedby'?: string
  'aria-invalid'?: boolean
  label: string
  options: EntitySelectOption[]
  onValueChange: (value: string) => void
  value?: string
  placeholder?: string
  searchPlaceholder?: string
  emptyText?: string
  disabled?: boolean
}

export function EntitySelect({
  id,
  'aria-describedby': ariaDescribedBy,
  'aria-invalid': ariaInvalid,
  label,
  options,
  onValueChange,
  value,
  placeholder = 'Select an entity',
  searchPlaceholder = 'Search entities',
  emptyText = 'No results found.',
  disabled,
}: EntitySelectProps) {
  const [open, setOpen] = useState(false)
  const [internalValue, setInternalValue] = useState('')
  const selectedValue = value ?? internalValue
  const selected = options.find((option) => option.value === selectedValue)

  function select(option: EntitySelectOption) {
    setInternalValue(option.value)
    onValueChange(option.value)
    setOpen(false)
  }

  return (
    <Dialog onOpenChange={setOpen} open={open}>
      <DialogTrigger asChild>
        <Button
          id={id}
          aria-describedby={ariaDescribedBy}
          aria-expanded={open}
          aria-invalid={ariaInvalid}
          aria-label={label}
          className="w-full justify-between"
          disabled={disabled}
          role="combobox"
          type="button"
          variant="outline"
        >
          {selected?.label ?? placeholder}
          <ChevronsUpDown aria-hidden="true" className="opacity-50" />
        </Button>
      </DialogTrigger>
      <DialogContent className="p-0" showCloseButton={false}>
        <DialogTitle className="sr-only">{label}</DialogTitle>
        <DialogDescription className="sr-only">
          Search and choose an option for {label}. Current selection:{' '}
          {selected?.label ?? 'None'}.
        </DialogDescription>
        <Command label={searchPlaceholder}>
          <CommandInput
            aria-label={searchPlaceholder}
            placeholder={searchPlaceholder}
          />
          <CommandList>
            <CommandEmpty>{emptyText}</CommandEmpty>
            <CommandGroup>
              {options.map((option) => (
                <CommandItem
                  disabled={option.disabled}
                  key={option.value}
                  keywords={option.keywords}
                  onSelect={() => select(option)}
                  value={`${option.label} ${option.value}`}
                >
                  <Check
                    aria-hidden="true"
                    className={cn(
                      'size-4',
                      selectedValue === option.value
                        ? 'opacity-100'
                        : 'opacity-0',
                    )}
                  />
                  {option.label}
                </CommandItem>
              ))}
            </CommandGroup>
          </CommandList>
        </Command>
      </DialogContent>
    </Dialog>
  )
}
